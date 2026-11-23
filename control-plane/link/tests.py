import uuid
from datetime import timedelta

from django.core.cache import cache
from django.test import TestCase, override_settings
from rest_framework.test import APIClient

from accounts.models import Account, Device, DeviceToken

from .models import LinkSession

PK = "A" * 43
ENV = {"sender_public_key": "B" * 43, "nonce": "C" * 16, "ciphertext": "D" * 142}


@override_settings(SECURE_SSL_REDIRECT=False)
class LinkTests(TestCase):
    def setUp(self):
        cache.clear()
        self.acct = Account.objects.create_user("me@example.com", "account password 1")
        d = Device.objects.create(account=self.acct, client_device_id="phone", name="Phone")
        _, raw = DeviceToken.issue(d)
        self.phone = APIClient()
        self.phone.credentials(HTTP_AUTHORIZATION=f"Bearer {raw}")
        self.laptop = APIClient()

    def start(self, pk=PK):
        r = self.laptop.post("/api/link/", {"public_key": pk, "client_device_id": "laptop-1", "name": "Clavium Web", "platform": "web"}, format="json")
        self.assertEqual(r.status_code, 201, r.content)
        return r.json()

    def test_full_flow_delivers_once(self):
        s = self.start()
        poll = f"/api/link/{s['id']}/?poll_token={s['poll_token']}"
        self.assertEqual(self.laptop.get(poll).json()["status"], "pending")
        info = self.phone.get(f"/api/link/{s['id']}/info/").json()
        self.assertEqual((info["name"], info["public_key"]), ("Clavium Web", PK))
        self.assertEqual(self.phone.post(f"/api/link/{s['id']}/approve/", {"public_key": PK, "envelope": ENV}, format="json").status_code, 200)

        got = self.laptop.get(poll).json()
        self.assertEqual(got["status"], "approved")
        self.assertEqual(got["envelope"], ENV)
        self.assertEqual(got["account"]["email"], "me@example.com")
        # The issued token works for the new device.
        c = APIClient()
        c.credentials(HTTP_AUTHORIZATION=f"Bearer {got['token']}")
        self.assertEqual(c.get("/api/accounts/devices/").status_code, 200)
        # Delivered exactly once; nothing secret stays on the server.
        self.assertEqual(self.laptop.get(poll).json(), {"status": "claimed"})
        row = LinkSession.objects.get(id=s["id"])
        self.assertEqual((row.raw_token, row.envelope), ("", None))

    def test_wrong_poll_token_and_unauthenticated_approval(self):
        s = self.start()
        self.assertEqual(self.laptop.get(f"/api/link/{s['id']}/?poll_token=nope").status_code, 404)
        self.assertEqual(self.laptop.post(f"/api/link/{s['id']}/approve/", {"public_key": PK, "envelope": ENV}, format="json").status_code, 401)

    def test_approval_must_target_the_registered_key(self):
        s = self.start()
        r = self.phone.post(f"/api/link/{s['id']}/approve/", {"public_key": "Z" * 43, "envelope": ENV}, format="json")
        self.assertEqual(r.status_code, 400)

    def test_expired_and_denied(self):
        s = self.start()
        LinkSession.objects.filter(id=s["id"]).update(created_at=LinkSession.objects.get(id=s["id"]).created_at - timedelta(minutes=3))
        self.assertEqual(self.phone.get(f"/api/link/{s['id']}/info/").status_code, 404)
        self.assertEqual(self.phone.post(f"/api/link/{s['id']}/approve/", {"public_key": PK, "envelope": ENV}, format="json").status_code, 410)
        self.assertEqual(self.laptop.get(f"/api/link/{s['id']}/?poll_token={s['poll_token']}").json()["status"], "expired")
        s2 = self.start()
        self.phone.post(f"/api/link/{s2['id']}/deny/")
        self.assertEqual(self.laptop.get(f"/api/link/{s2['id']}/?poll_token={s2['poll_token']}").json()["status"], "denied")

    def test_bad_inputs(self):
        r = self.laptop.post("/api/link/", {"public_key": "short", "client_device_id": "x", "name": "x"}, format="json")
        self.assertEqual(r.status_code, 400)
        s = self.start()
        bad = dict(ENV, nonce="not valid!")
        self.assertEqual(self.phone.post(f"/api/link/{s['id']}/approve/", {"public_key": PK, "envelope": bad}, format="json").status_code, 400)
        self.assertEqual(self.laptop.get(f"/api/link/{uuid.uuid4()}/?poll_token=x").status_code, 404)
