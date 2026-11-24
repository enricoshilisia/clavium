import re
from datetime import timedelta

from django.core import mail
from django.core.cache import cache
from django.test import TestCase, override_settings
from django.utils import timezone
from rest_framework.test import APIClient

from .models import Account, Device, DeviceToken, EmailVerification

PW = "account password 1"
BASE = dict(SECURE_SSL_REDIRECT=False, EMAIL_BACKEND="django.core.mail.backends.locmem.EmailBackend", CLAVIUM_PUBLIC_URL="https://api.test")


def code_from(message) -> str:
    return re.search(r"\b(\d{6})\b", message.body).group(1)


def link_token_from(message) -> str:
    return re.search(r"/verify-email/\?t=([\w-]+)", message.body).group(1)


class Base(TestCase):
    def setUp(self):
        cache.clear()
        self.c = APIClient()

    def register(self, email="new@example.com"):
        r = self.c.post("/api/accounts/register/", {"email": email, "password": PW}, format="json")
        self.assertEqual(r.status_code, 201, r.content)
        return r.json()

    def sign_in(self, email="new@example.com", device="d1"):
        return self.c.post(
            "/api/accounts/devices/register/",
            {"email": email, "password": PW, "client_device_id": device, "name": "Laptop"},
            format="json",
        )


@override_settings(**BASE, CLAVIUM_EMAIL_VERIFICATION="off")
class OffTests(Base):
    def test_off_sends_nothing_and_blocks_nothing(self):
        body = self.register()
        self.assertEqual((body["email_verified"], body["email_verification"]), (False, "off"))
        self.assertEqual(len(mail.outbox), 0)
        self.assertEqual(self.sign_in().status_code, 201)
        self.assertEqual(self.c.post("/api/accounts/email/send/", {"email": "new@example.com"}, format="json").status_code, 404)
        self.assertEqual(self.c.get("/verify-email/?t=x").status_code, 404)


@override_settings(**BASE, CLAVIUM_EMAIL_VERIFICATION="optional")
class OptionalTests(Base):
    def test_sends_on_register_but_does_not_block(self):
        self.register()
        self.assertEqual(len(mail.outbox), 1)
        msg = mail.outbox[0]
        self.assertEqual(msg.to, ["new@example.com"])
        self.assertIn(code_from(msg), msg.subject)
        self.assertIn("https://api.test/verify-email/?t=", msg.body)
        self.assertEqual(len(msg.alternatives), 1)
        r = self.sign_in()
        self.assertEqual(r.status_code, 201)
        self.assertFalse(r.json()["account"]["email_verified"])

    def test_code_verifies(self):
        self.register()
        code = code_from(mail.outbox[0])
        r = self.c.post("/api/accounts/email/verify/", {"email": "NEW@example.com", "code": code}, format="json")
        self.assertEqual(r.status_code, 200, r.content)
        self.assertTrue(Account.objects.get().email_verified)
        # A used code is not reusable, but asking again is harmless.
        self.assertEqual(self.c.post("/api/accounts/email/verify/", {"email": "new@example.com", "code": code}, format="json").json(), {"email_verified": True})

    def test_wrong_codes_burn_the_challenge(self):
        self.register()
        code = code_from(mail.outbox[0])
        wrong = "000000" if code != "000000" else "111111"
        for _ in range(EmailVerification.CODE_ATTEMPTS):
            cache.clear()
            self.assertEqual(self.c.post("/api/accounts/email/verify/", {"email": "new@example.com", "code": wrong}, format="json").status_code, 400)
        cache.clear()
        self.assertEqual(self.c.post("/api/accounts/email/verify/", {"email": "new@example.com", "code": code}, format="json").status_code, 400)
        self.assertFalse(Account.objects.get().email_verified)

    def test_expired_code_fails(self):
        self.register()
        EmailVerification.objects.update(expires_at=timezone.now() - timedelta(seconds=1))
        code = code_from(mail.outbox[0])
        self.assertEqual(self.c.post("/api/accounts/email/verify/", {"email": "new@example.com", "code": code}, format="json").status_code, 400)

    def test_resend_cooldown_and_old_code_stops_working(self):
        self.register()
        old = code_from(mail.outbox[0])
        self.c.post("/api/accounts/email/send/", {"email": "new@example.com"}, format="json")
        self.assertEqual(len(mail.outbox), 1, "within a minute nothing new is sent")
        EmailVerification.objects.update(created_at=timezone.now() - timedelta(minutes=2))
        cache.clear()
        self.assertEqual(self.c.post("/api/accounts/email/send/", {"email": "new@example.com"}, format="json").status_code, 202)
        self.assertEqual(len(mail.outbox), 2)
        new = code_from(mail.outbox[1])
        if old != new:
            self.assertEqual(self.c.post("/api/accounts/email/verify/", {"email": "new@example.com", "code": old}, format="json").status_code, 400)
        cache.clear()
        self.assertEqual(self.c.post("/api/accounts/email/verify/", {"email": "new@example.com", "code": new}, format="json").status_code, 200)

    def test_send_does_not_reveal_accounts(self):
        r = self.c.post("/api/accounts/email/send/", {"email": "nobody@example.com"}, format="json")
        self.assertEqual(r.status_code, 202)
        self.assertEqual(len(mail.outbox), 0)

    def test_link_needs_a_post(self):
        self.register()
        token = link_token_from(mail.outbox[0])
        page = self.c.get(f"/verify-email/?t={token}")
        self.assertEqual(page.status_code, 200)
        self.assertContains(page, "Confirm my email")
        self.assertFalse(Account.objects.get().email_verified, "opening the link alone must not verify")
        done = self.c.post("/verify-email/", {"t": token})
        self.assertContains(done, "Email confirmed")
        self.assertTrue(Account.objects.get().email_verified)
        self.assertEqual(self.c.post("/verify-email/", {"t": token}).status_code, 400)

    def test_signed_in_status_and_resend(self):
        self.register()
        token = self.sign_in().json()["token"]
        self.c.credentials(HTTP_AUTHORIZATION=f"Bearer {token}")
        me = self.c.get("/api/accounts/me/").json()
        self.assertEqual((me["email"], me["email_verified"], me["email_verification"]), ("new@example.com", False, "optional"))
        self.assertEqual(self.c.post("/api/accounts/email/send/", {}, format="json").status_code, 429)
        code = code_from(mail.outbox[0])
        self.assertEqual(self.c.post("/api/accounts/email/verify/", {"code": code}, format="json").status_code, 200)
        self.assertTrue(self.c.get("/api/accounts/me/").json()["email_verified"])

    def test_old_address_message_cannot_verify_new_address(self):
        self.register()
        code = code_from(mail.outbox[0])
        Account.objects.update(email="changed@example.com")
        self.assertEqual(self.c.post("/api/accounts/email/verify/", {"email": "changed@example.com", "code": code}, format="json").status_code, 400)


@override_settings(**BASE, CLAVIUM_EMAIL_VERIFICATION="required")
class RequiredTests(Base):
    def test_blocks_new_sign_in_until_verified(self):
        self.register()
        r = self.sign_in()
        self.assertEqual(r.status_code, 403)
        self.assertEqual(r.json()["code"], "email_not_verified")
        code = code_from(mail.outbox[0])
        cache.clear()
        self.assertEqual(self.c.post("/api/accounts/email/verify/", {"email": "new@example.com", "code": code}, format="json").status_code, 200)
        r = self.sign_in()
        self.assertEqual(r.status_code, 201)
        self.assertTrue(r.json()["account"]["email_verified"])

    def test_wrong_password_does_not_leak_verification_state(self):
        self.register()
        r = self.c.post(
            "/api/accounts/devices/register/",
            {"email": "new@example.com", "password": "wrong password", "client_device_id": "d1", "name": "x"},
            format="json",
        )
        self.assertEqual(r.status_code, 401)

    def test_already_signed_in_devices_keep_working(self):
        acct = Account.objects.create_user("old@example.com", PW)
        _, raw = DeviceToken.issue(Device.objects.create(account=acct, client_device_id="x", name="Old laptop"))
        self.c.credentials(HTTP_AUTHORIZATION=f"Bearer {raw}")
        self.assertEqual(self.c.get("/api/accounts/devices/").status_code, 200)

    def test_console_login_blocked(self):
        Account.objects.create_user("admin@example.com", PW)
        r = self.client.post("/console/login/", {"email": "admin@example.com", "password": PW})
        self.assertEqual(r.status_code, 403)
        self.assertContains(r, "Verify your email address first", status_code=403)
        self.assertEqual(len(mail.outbox), 1)

    def test_mark_existing_command(self):
        from django.core.management import call_command

        Account.objects.create_user("old@example.com", PW)
        call_command("email_verification", "--mark-existing", stdout=open("/dev/null", "w"))
        self.assertEqual(self.sign_in("old@example.com").status_code, 201)
