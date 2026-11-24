import base64
import hashlib
import os
import uuid
from datetime import timedelta

from django.core.cache import cache
from django.core.management import call_command
from django.test import TestCase, override_settings
from django.utils import timezone
from rest_framework.test import APIClient

from accounts.models import Account, Device, DeviceToken
from orgs.models import Membership, Organization, OrgPolicy

from .models import Share


def b64(n):
    return base64.b64encode(os.urandom(n)).decode()


def draft(salt=False, **kw):
    auth = os.urandom(32)
    body = {
        "id": str(uuid.uuid4()), "nonce": b64(12), "ciphertext": b64(200), "salt": b64(16) if salt else "",
        "rounds": 600000, "auth_hash": hashlib.sha256(auth).hexdigest(), **kw,
    }
    return body, base64.urlsafe_b64encode(auth).decode().rstrip("=")


@override_settings(SECURE_SSL_REDIRECT=False, CLAVIUM_PUBLIC_URL="https://api.test")
class ShareTests(TestCase):
    def setUp(self):
        cache.clear()
        self.acct = Account.objects.create_user("me@example.com", "account password 1")
        _, raw = DeviceToken.issue(Device.objects.create(account=self.acct, client_device_id="d", name="Laptop"))
        self.me = APIClient()
        self.me.credentials(HTTP_AUTHORIZATION=f"Bearer {raw}")
        self.anon = APIClient()

    def create(self, **kw):
        body, auth = draft(**kw)
        r = self.me.post("/api/shares/", body, format="json")
        self.assertEqual(r.status_code, 201, r.content)
        return r.json(), auth, body

    def open(self, sid, auth):
        return self.anon.post(f"/api/shares/{sid}/open/", {"auth": auth}, format="json")

    def test_one_view_then_gone(self):
        s, auth, body = self.create()
        self.assertEqual(s["url"], f"https://api.test/s/{s['id']}")
        meta = self.anon.get(f"/api/shares/{s['id']}/meta/").json()
        self.assertEqual((meta["has_passphrase"], meta["views_left"]), (False, 1))
        r = self.open(s["id"], auth)
        self.assertEqual(r.status_code, 200)
        self.assertEqual((r.json()["ciphertext"], r.json()["views_left"]), (body["ciphertext"], 0))
        self.assertEqual(Share.objects.get().ciphertext, "", "wiped after the last view")
        self.assertEqual(self.open(s["id"], auth).status_code, 410)
        self.assertEqual(self.anon.get(f"/api/shares/{s['id']}/meta/").status_code, 410)
        self.assertEqual(self.me.get("/api/shares/").json()[0]["status"], "used")

    def test_wrong_auth_is_counted_and_locks(self):
        s, auth, _ = self.create(salt=True, max_views=3)
        bad = base64.urlsafe_b64encode(os.urandom(32)).decode().rstrip("=")
        for i in range(Share.MAX_FAILED):
            cache.clear()
            r = self.open(s["id"], bad)
            self.assertEqual(r.status_code, 403)
            self.assertIn("Wrong passphrase", r.json()["detail"])
        cache.clear()
        self.assertEqual(self.open(s["id"], auth).status_code, 410, "locked after too many wrong tries")
        self.assertEqual(Share.objects.get().ciphertext, "")

    def test_meta_does_not_use_a_view_and_garbage_is_refused(self):
        s, auth, _ = self.create(max_views=2)
        for _ in range(3):
            self.anon.get(f"/api/shares/{s['id']}/meta/")
        self.assertEqual(Share.objects.get().views, 0)
        self.assertEqual(self.open(s["id"], "not-base64!!").status_code, 403)
        self.assertEqual(self.open(s["id"], auth).json()["views_left"], 1)

    def test_revoke_and_expiry(self):
        s, auth, _ = self.create()
        self.assertEqual(self.me.delete(f"/api/shares/{s['id']}/").status_code, 204)
        self.assertEqual(self.open(s["id"], auth).status_code, 410)
        s2, auth2, _ = self.create(expires_in_hours=1)
        Share.objects.filter(id=s2["id"]).update(expires_at=timezone.now() - timedelta(seconds=1))
        self.assertEqual(self.open(s2["id"], auth2).status_code, 410)
        call_command("shares_cleanup", verbosity=0)
        self.assertEqual(Share.objects.get(id=s2["id"]).ciphertext, "")

    def test_limits_and_validation(self):
        body, _ = draft(max_views=50)
        self.assertEqual(self.me.post("/api/shares/", body, format="json").status_code, 400)
        body, _ = draft(expires_in_hours=10_000)
        self.assertEqual(self.me.post("/api/shares/", body, format="json").status_code, 400)
        body, _ = draft(auth_hash="nothex")
        self.assertEqual(self.me.post("/api/shares/", body, format="json").status_code, 400)
        self.assertEqual(self.anon.post("/api/shares/", draft()[0], format="json").status_code, 401)

    def test_organization_can_turn_it_off(self):
        org = Organization.objects.create(name="Strict", created_by=self.acct)
        Membership.objects.create(organization=org, account=self.acct, role="owner")
        OrgPolicy.objects.create(organization=org, allow_share_links=False)
        r = self.me.post("/api/shares/", draft()[0], format="json")
        self.assertEqual(r.status_code, 403)
        self.assertFalse(self.me.get("/api/orgs/policy/mine/").json()["allow_share_links"])

    def test_page_is_locked_down(self):
        s, _, _ = self.create()
        r = self.anon.get(f"/s/{s['id']}")
        self.assertEqual(r.status_code, 200)
        csp = r["Content-Security-Policy"]
        self.assertIn("default-src 'none'", csp)
        self.assertIn("script-src 'nonce-", csp)
        self.assertEqual((r["Referrer-Policy"], r["Cache-Control"]), ("no-referrer", "no-store"))
        nonce = csp.split("'nonce-")[1].split("'")[0]
        self.assertContains(r, f'<script nonce="{nonce}">')
