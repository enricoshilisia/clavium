from datetime import timedelta
from unittest import mock

from django.core import mail
from django.core.cache import cache
from django.core.management import call_command
from django.test import TestCase, override_settings
from django.utils import timezone
from rest_framework.test import APIClient

from accounts.models import Account, Device, DeviceToken
from orgs.models import HealthSnapshot, Membership, Organization, OrgPolicy

from . import hibp
from .models import EmailBreachStatus

BREACH = {"name": "Adobe", "title": "Adobe", "domain": "adobe.com", "date": "2013-10-04", "data": ["Email addresses", "Passwords"]}
NEW = {"name": "Kenya2026", "title": "Example Kenya Leak", "domain": "example.co.ke", "date": "2026-10-01", "data": ["Email addresses", "Phone numbers"]}


def client_for(acct):
    _, raw = DeviceToken.issue(Device.objects.create(account=acct, client_device_id=str(acct.id), name="Laptop"))
    c = APIClient()
    c.credentials(HTTP_AUTHORIZATION=f"Bearer {raw}")
    return c


@override_settings(SECURE_SSL_REDIRECT=False, CLAVIUM_HIBP_API_KEY="k", CLAVIUM_HIBP_RPM=6000, EMAIL_BACKEND="django.core.mail.backends.locmem.EmailBackend")
class BreachTests(TestCase):
    def setUp(self):
        cache.clear()
        self.alice = Account.objects.create_user("alice@contoso.com", "account password 1")
        self.bob = Account.objects.create_user("bob@gmail.com", "account password 1")
        self.org = Organization.objects.create(name="Contoso", created_by=self.alice)
        Membership.objects.create(organization=self.org, account=self.alice, role="owner")
        self.policy = OrgPolicy.objects.create(organization=self.org)

    def test_only_opted_in_or_org_enabled_people_are_checked(self):
        with mock.patch.object(hibp, "breaches_for", return_value=[BREACH]) as m:
            call_command("breach_emails", verbosity=0)
            self.assertEqual(m.call_count, 0, "nobody monitored yet")
            self.policy.check_email_breaches = True
            self.policy.save()
            call_command("breach_emails", verbosity=0)
            self.assertEqual([c.args[0] for c in m.call_args_list], ["alice@contoso.com"])
            # Not due again for a week.
            call_command("breach_emails", verbosity=0)
            self.assertEqual(m.call_count, 1)
        self.assertEqual(EmailBreachStatus.objects.get(account=self.alice).names(), ["Adobe"])

    def test_new_breach_sends_an_email_but_the_first_check_does_not(self):
        self.policy.check_email_breaches = True
        self.policy.save()
        with mock.patch.object(hibp, "breaches_for", return_value=[BREACH]):
            call_command("breach_emails", verbosity=0)
        self.assertEqual(len(mail.outbox), 0)
        EmailBreachStatus.objects.update(checked_at=timezone.now() - timedelta(days=8))
        with mock.patch.object(hibp, "breaches_for", return_value=[NEW, BREACH]):
            call_command("breach_emails", verbosity=0)
        self.assertEqual(len(mail.outbox), 1)
        self.assertIn("Example Kenya Leak", mail.outbox[0].body)
        self.assertEqual(mail.outbox[0].to, ["alice@contoso.com"])

    def test_people_can_opt_in_themselves(self):
        c = client_for(self.bob)
        self.assertEqual(c.get("/api/breaches/mine/").json()["monitored"], False)
        with mock.patch.object(hibp, "breaches_for", return_value=[BREACH]) as m:
            r = c.post("/api/breaches/mine/", {"enabled": True}, format="json")
            self.assertEqual(m.call_args.args[0], "bob@gmail.com")
        body = r.json()
        self.assertEqual((body["monitored"], body["opted_in"], body["breaches"][0]["name"]), (True, True, "Adobe"))
        c.post("/api/breaches/mine/", {"enabled": False}, format="json")
        self.assertEqual(c.get("/api/breaches/mine/").json()["monitored"], False)

    @override_settings(CLAVIUM_HIBP_API_KEY="")
    def test_hidden_without_a_key(self):
        c = client_for(self.bob)
        self.assertEqual(c.get("/api/breaches/mine/").json()["available"], False)
        self.assertEqual(c.post("/api/breaches/mine/", {"enabled": True}, format="json").status_code, 404)

    def test_health_report_carries_breached_count_and_console_shows_it(self):
        c = client_for(self.alice)
        r = c.post("/api/orgs/health/", {"score": 70, "total": 10, "weak": 1, "reused": 2, "old": 0, "without_totp": 3, "breached": 2}, format="json")
        self.assertEqual(r.status_code, 204)
        self.assertEqual(HealthSnapshot.objects.get(account=self.alice).breached, 2)
        # Older apps that do not send it still work.
        self.assertEqual(c.post("/api/orgs/health/", {"score": 70, "total": 10, "weak": 1, "reused": 2, "old": 0, "without_totp": 3}, format="json").status_code, 204)
        HealthSnapshot.objects.filter(account=self.alice).update(breached=2)
        EmailBreachStatus.objects.create(account=self.alice, breaches=[BREACH], checked_at=timezone.now())
        self.client.force_login(self.alice)
        page = self.client.get(f"/console/{self.org.id}/")
        self.assertContains(page, "2 breached")
        self.assertContains(page, "email in 1 breach")
