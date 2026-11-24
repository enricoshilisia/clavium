import base64
import json
from unittest import mock
from urllib.parse import parse_qs, urlparse

from django.core import mail
from django.core.cache import cache
from django.test import TestCase, override_settings

from accounts.models import Account, Device, DeviceToken
from orgs.models import AuditLogEntry, Membership, Organization

from . import graph, sync
from .models import DirectoryConnection

PW = "account password 1"
MS = dict(
    SECURE_SSL_REDIRECT=False,
    EMAIL_BACKEND="django.core.mail.backends.locmem.EmailBackend",
    CLAVIUM_PUBLIC_URL="https://api.test",
    CLAVIUM_MS_CLIENT_ID="client-123",
    CLAVIUM_MS_CLIENT_SECRET="s3cret",
)
TENANT = "11111111-2222-3333-4444-555555555555"


def user(i, enabled=True, guest=False, email=None):
    return {"id": f"u{i}", "name": f"User {i}", "email": f"user{i}@contoso.com" if email is None else email, "enabled": enabled, "guest": guest}


class FakeGraph:
    def __init__(self, groups, fail=False):
        self.groups = groups  # group id -> list of users
        self.fail = fail

    def group_users(self, gid):
        if self.fail:
            raise graph.GraphError("Microsoft Graph error 503")
        return list(self.groups.get(gid, []))

    def group(self, gid):
        return {"id": gid, "name": f"Group {gid}"}

    def search_groups(self, q):
        return [{"id": gid, "name": f"Group {gid}", "description": "", "mail": ""} for gid in self.groups if q.lower() in gid.lower()]

    def check(self):
        if self.fail:
            raise graph.GraphError("missing permission")


@override_settings(**MS)
class SyncTests(TestCase):
    def setUp(self):
        cache.clear()
        self.owner = Account.objects.create_user("owner@contoso.com", PW)
        self.org = Organization.objects.create(name="Contoso", created_by=self.owner)
        self.owner_m = Membership.objects.create(organization=self.org, account=self.owner, role=Membership.Role.OWNER)
        self.conn = DirectoryConnection.objects.create(organization=self.org, tenant_id=TENANT, groups=[{"id": "staff", "name": "Staff"}])

    def run_sync(self, groups, **kw):
        self.conn.refresh_from_db()
        return sync.run(self.conn, client=FakeGraph(groups), **kw)

    def active(self):
        return set(Membership.objects.filter(organization=self.org, removed_at__isnull=True).values_list("account__email", flat=True))

    def test_adds_people_and_emails_invites(self):
        r = self.run_sync({"staff": [user(1), user(2), user(3, enabled=False), user(4, guest=True), user(5, email="")]})
        self.assertEqual(sorted(r["added"]), ["user1@contoso.com", "user2@contoso.com"])
        self.assertEqual(self.active(), {"owner@contoso.com", "user1@contoso.com", "user2@contoso.com"})
        self.assertEqual(r["invites_emailed"], 2)
        self.assertEqual(len(mail.outbox), 2)
        self.assertIn("https://api.test/console/invite/", mail.outbox[0].body)
        self.assertIn("Contoso", mail.outbox[0].subject)
        m = Membership.objects.get(account__email="user1@contoso.com")
        self.assertTrue(m.entra_managed)
        self.assertEqual(m.external_id, "u1")
        self.assertFalse(m.account.has_usable_password())
        # Running again changes nothing and sends nothing.
        r = self.run_sync({"staff": [user(1), user(2)]})
        self.assertEqual(r["added"], [])
        self.assertEqual(len(mail.outbox), 2)

    def test_guests_when_allowed(self):
        self.conn.include_guests = True
        self.conn.save()
        r = self.run_sync({"staff": [user(4, guest=True)]})
        self.assertEqual(r["added"], ["user4@contoso.com"])

    def test_links_existing_member_instead_of_duplicating(self):
        acct = Account.objects.create_user("user1@contoso.com", PW)
        Membership.objects.create(organization=self.org, account=acct, role=Membership.Role.MEMBER)
        r = self.run_sync({"staff": [user(1, email="USER1@contoso.com".lower())]})
        self.assertEqual(r["linked"], ["user1@contoso.com"])
        self.assertEqual(Membership.objects.filter(account=acct).count(), 1)
        self.assertEqual(len(mail.outbox), 0, "has a password already, no invite")

    def test_disabled_and_leavers_are_offboarded(self):
        self.run_sync({"staff": [user(i) for i in range(1, 11)]})
        m1 = Membership.objects.get(account__email="user1@contoso.com")
        m1.account.set_password(PW)
        m1.account.save()
        d = Device.objects.create(account=m1.account, client_device_id="x", name="Laptop")
        _, raw = DeviceToken.issue(d)
        r = self.run_sync({"staff": [user(1, enabled=False)] + [user(i) for i in range(3, 11)]})
        self.assertEqual(sorted(r["removed"]), ["user1@contoso.com", "user2@contoso.com"])
        self.assertNotIn("user1@contoso.com", self.active())
        d.refresh_from_db()
        self.assertIsNotNone(d.revoked_at)
        self.assertIsNone(DeviceToken.authenticate(raw))
        self.assertFalse(Account.objects.get(email="user1@contoso.com").is_active)
        entry = AuditLogEntry.objects.filter(action="member.removed", metadata__member_email="user1@contoso.com").get()
        self.assertIn("disabled in Microsoft 365", entry.metadata["source"])

    def test_mass_removal_is_held_until_approved(self):
        self.run_sync({"staff": [user(i) for i in range(1, 21)]})
        r = self.run_sync({"staff": [user(i) for i in range(1, 11)]})
        self.assertTrue(r["held"])
        self.assertEqual(r["removed"], [])
        self.assertEqual(len(self.active()), 21)
        self.conn.refresh_from_db()
        self.assertEqual(self.conn.status, DirectoryConnection.Status.HELD)
        self.assertEqual(len(self.conn.held_removals), 10)
        r = self.run_sync({"staff": [user(i) for i in range(1, 11)]}, approve_removals=True)
        self.assertEqual(len(r["removed"]), 10)
        self.conn.refresh_from_db()
        self.assertEqual((self.conn.status, self.conn.held_removals), (DirectoryConnection.Status.ACTIVE, []))

    def test_empty_directory_never_removes(self):
        self.run_sync({"staff": [user(1), user(2)]})
        r = self.run_sync({"staff": []})
        self.assertTrue(r["held"])
        self.assertEqual(len(self.active()), 3)

    def test_graph_failure_changes_nothing(self):
        self.run_sync({"staff": [user(1)]})
        self.conn.refresh_from_db()
        r = sync.run(self.conn, client=FakeGraph({}, fail=True))
        self.assertIn("503", r["error"])
        self.assertIn("user1@contoso.com", self.active())
        self.conn.refresh_from_db()
        self.assertEqual(self.conn.status, DirectoryConnection.Status.ERROR)

    def test_admin_group_promotes_and_demotes_but_never_touches_owner(self):
        self.conn.admin_group_id = "admins"
        self.conn.save()
        owner_user = user(9, email="owner@contoso.com")
        self.run_sync({"staff": [user(1), user(2), owner_user], "admins": [user(1)]})
        role = lambda e: Membership.objects.get(account__email=e).role
        self.assertEqual((role("user1@contoso.com"), role("user2@contoso.com"), role("owner@contoso.com")), ("admin", "member", "owner"))
        r = self.run_sync({"staff": [user(1), user(2), owner_user], "admins": [user(2)]})
        self.assertEqual((r["promoted"], r["demoted"]), (["user2@contoso.com"], ["user1@contoso.com"]))
        self.assertEqual(role("owner@contoso.com"), "owner")

    def test_last_owner_is_never_removed(self):
        self.run_sync({"staff": [user(9, email="owner@contoso.com"), user(1)]})
        r = self.run_sync({"staff": [user(1)]})
        self.assertEqual(r["kept_last_owner"], ["owner@contoso.com"])
        self.assertIn("owner@contoso.com", self.active())

    def test_auto_remove_off_only_reports(self):
        self.conn.auto_remove = False
        self.conn.save()
        self.run_sync({"staff": [user(1), user(2)]})
        r = self.run_sync({"staff": [user(1)]})
        self.assertEqual(r["removed"], [])
        self.assertEqual([x["email"] for x in r["not_in_directory"]], ["user2@contoso.com"])
        self.assertIn("user2@contoso.com", self.active())

    def test_returner_is_reactivated_with_a_new_invite(self):
        self.run_sync({"staff": [user(1), user(2)]})
        self.run_sync({"staff": [user(2)]})
        self.assertNotIn("user1@contoso.com", self.active())
        r = self.run_sync({"staff": [user(1), user(2)]})
        self.assertEqual(r["reactivated"], ["user1@contoso.com"])
        self.assertTrue(Account.objects.get(email="user1@contoso.com").is_active)
        self.assertEqual(len(mail.outbox), 3)

    def test_team_vault_group_rule_follows_the_directory(self):
        import uuid as _uuid

        from teams.models import TeamAccess, TeamGroupRule, TeamVault

        team = TeamVault.objects.create(id=_uuid.uuid4(), organization=self.org, name="Finance")
        # The rule's group is not one of the "Clavium" groups; sync reads it anyway.
        TeamGroupRule.objects.create(team=team, group_id="finance", group_name="Finance", role="editor")
        r = self.run_sync({"staff": [user(1), user(2)], "finance": [user(2)]})
        self.assertEqual(r["team_access"]["added"], 1)
        self.assertEqual(list(TeamAccess.objects.filter(team=team).values_list("account__email", "source")), [("user2@contoso.com", "group")])
        self.assertEqual(Membership.objects.get(account__email="user2@contoso.com").entra_groups, ["finance", "staff"])
        r = self.run_sync({"staff": [user(1), user(2)], "finance": []})
        self.assertEqual(r["team_access"]["removed"], 1)
        self.assertFalse(TeamAccess.objects.filter(team=team).exists())

    def test_paused_is_skipped_by_the_timer(self):
        self.conn.status = DirectoryConnection.Status.PAUSED
        self.conn.save()
        with mock.patch.object(graph, "client_for", return_value=FakeGraph({"staff": [user(1)]})):
            self.assertEqual(sync.run_all(), 0)
        self.assertNotIn("user1@contoso.com", self.active())


def id_token(**claims):
    enc = lambda d: base64.urlsafe_b64encode(json.dumps(d).encode()).decode().rstrip("=")
    return f"{enc({'alg': 'RS256'})}.{enc(claims)}.sig"


@override_settings(**MS)
class ConnectFlowTests(TestCase):
    def setUp(self):
        cache.clear()
        self.owner = Account.objects.create_user("owner@contoso.com", PW)
        self.org = Organization.objects.create(name="Contoso", created_by=self.owner)
        Membership.objects.create(organization=self.org, account=self.owner, role=Membership.Role.OWNER)
        self.client.force_login(self.owner)
        self.fake = FakeGraph({"staff": [user(1)], "sales": []})
        p = mock.patch.object(graph, "client_for", return_value=self.fake)
        p.start()
        self.addCleanup(p.stop)

    def start(self):
        r = self.client.post(f"/console/{self.org.id}/microsoft/connect/")
        self.assertEqual(r.status_code, 302)
        url = urlparse(r["Location"])
        self.assertEqual(url.path, "/organizations/v2.0/adminconsent")
        q = parse_qs(url.query)
        self.assertEqual(q["redirect_uri"], ["https://api.test/console/microsoft/consented/"])
        return q["state"][0]

    def consent(self, state, tenant=TENANT):
        r = self.client.get("/console/microsoft/consented/", {"admin_consent": "True", "tenant": tenant, "state": state})
        self.assertEqual(r.status_code, 302)
        q = parse_qs(urlparse(r["Location"]).query)
        return q["state"][0], q["nonce"][0], r["Location"]

    def finish(self, state, claims):
        body = {"id_token": id_token(**claims), "access_token": "x"}
        with mock.patch("entra.views._request", return_value=(200, {}, body)):
            return self.client.get("/console/microsoft/signed-in/", {"code": "abc", "state": state})

    def test_full_connect(self):
        s2, nonce, loc = self.consent(self.start())
        self.assertIn(f"/{TENANT}/oauth2/v2.0/authorize", loc)
        r = self.finish(s2, {"tid": TENANT, "aud": "client-123", "nonce": nonce, "preferred_username": "admin@contoso.com"})
        self.assertEqual(r.status_code, 302)
        conn = DirectoryConnection.objects.get()
        self.assertEqual((conn.organization_id, conn.tenant_id, conn.status), (self.org.id, TENANT, "needs_groups"))
        self.assertTrue(AuditLogEntry.objects.filter(action="directory.connected").exists())

    def test_forged_tenant_is_rejected(self):
        # Attacker edits the unsigned consent redirect to claim a victim tenant,
        # then signs in with their own Microsoft account.
        s2, nonce, _ = self.consent(self.start(), tenant="victim-tenant")
        r = self.finish(s2, {"tid": TENANT, "aud": "client-123", "nonce": nonce})
        self.assertEqual(r.status_code, 302)
        self.assertFalse(DirectoryConnection.objects.exists())
        self.assertTrue(AuditLogEntry.objects.filter(action="directory.connect_rejected").exists())

    def test_wrong_nonce_or_audience_is_rejected(self):
        s2, nonce, _ = self.consent(self.start())
        self.finish(s2, {"tid": TENANT, "aud": "someone-else", "nonce": nonce})
        self.assertFalse(DirectoryConnection.objects.exists())

    def test_bad_or_replayed_state_is_rejected(self):
        self.start()
        r = self.client.get("/console/microsoft/consented/", {"admin_consent": "True", "tenant": TENANT, "state": "guess"})
        self.assertEqual(r.status_code, 302)
        self.assertNotIn("authorize", r["Location"])
        r = self.client.get("/console/microsoft/signed-in/", {"code": "abc", "state": "guess"})
        self.assertFalse(DirectoryConnection.objects.exists())

    def test_consent_cancelled(self):
        state = self.start()
        r = self.client.get("/console/microsoft/consented/", {"error": "access_denied", "state": state}, follow=True)
        self.assertContains(r, "approval was cancelled")

    def test_members_cannot_connect(self):
        bob = Account.objects.create_user("bob@contoso.com", PW)
        Membership.objects.create(organization=self.org, account=bob, role=Membership.Role.MEMBER)
        self.client.force_login(bob)
        r = self.client.post(f"/console/{self.org.id}/microsoft/connect/")
        self.assertNotIn("login.microsoftonline.com", r.get("Location", ""))

    def test_tenant_can_only_feed_one_org(self):
        other = Organization.objects.create(name="Other", created_by=self.owner)
        DirectoryConnection.objects.create(organization=other, tenant_id=TENANT)
        s2, nonce, _ = self.consent(self.start())
        r = self.finish(s2, {"tid": TENANT, "aud": "client-123", "nonce": nonce})
        self.assertEqual(DirectoryConnection.objects.filter(organization=self.org).count(), 0)

    def test_console_card_search_add_and_sync(self):
        DirectoryConnection.objects.create(organization=self.org, tenant_id=TENANT)
        page = self.client.get(f"/console/{self.org.id}/", {"ms_q": "sta"})
        self.assertContains(page, "Group staff")
        self.assertNotContains(page, "Group sales")
        self.client.post(f"/console/{self.org.id}/microsoft/action/", {"action": "add_group", "group_id": "staff"})
        conn = DirectoryConnection.objects.get()
        self.assertEqual((conn.group_ids(), conn.status), (["staff"], "active"))
        r = self.client.post(f"/console/{self.org.id}/microsoft/action/", {"action": "sync"}, follow=True)
        self.assertContains(r, "Sync complete: 1 added")
        self.assertContains(r, "Microsoft 365</span>")
        self.client.post(f"/console/{self.org.id}/microsoft/action/", {"action": "disconnect"})
        self.assertFalse(DirectoryConnection.objects.exists())
        self.assertFalse(Membership.objects.filter(entra_managed=True).exists())

    @override_settings(CLAVIUM_MS_CLIENT_ID="")
    def test_hidden_when_not_configured(self):
        page = self.client.get(f"/console/{self.org.id}/")
        self.assertContains(page, "not set up on this Clavium server")


class FakeSubGraph(FakeGraph):
    def __init__(self, groups, renew_status=None):
        super().__init__(groups)
        self.created, self.renewed, self.deleted = [], [], []
        self.renew_status = renew_status

    def create_subscription(self, url, state, expires):
        self.created.append((url, state))
        return {"id": f"sub-{len(self.created)}", "expires": ""}

    def renew_subscription(self, sub_id, expires):
        if self.renew_status:
            raise graph.GraphError("gone", status=self.renew_status)
        self.renewed.append(sub_id)

    def delete_subscription(self, sub_id):
        self.deleted.append(sub_id)


@override_settings(**MS)
class NotificationTests(TestCase):
    def setUp(self):
        cache.clear()
        self.owner = Account.objects.create_user("owner@contoso.com", PW)
        self.org = Organization.objects.create(name="Contoso", created_by=self.owner)
        Membership.objects.create(organization=self.org, account=self.owner, role=Membership.Role.OWNER)
        self.conn = DirectoryConnection.objects.create(
            organization=self.org, tenant_id=TENANT, status="active", groups=[{"id": "staff", "name": "Staff"}]
        )

    def subscribe(self, fake):
        from . import notifications

        self.assertEqual(notifications.ensure_subscription(self.conn, client=fake), "created")
        url, state = fake.created[-1]
        self.assertEqual(url, "https://api.test/api/entra/notify/")
        return state

    def notify(self, items):
        return self.client.post("/api/entra/notify/", json.dumps({"value": items}), content_type="application/json")

    def test_validation_handshake_echoes_token(self):
        r = self.client.post("/api/entra/notify/?validationToken=abc%20123")
        self.assertEqual((r.status_code, r.content, r["Content-Type"]), (200, b"abc 123", "text/plain"))

    def test_notification_marks_due_only_with_the_right_secret(self):
        state = self.subscribe(FakeSubGraph({}))
        sub = self.conn.subscription_id
        self.assertEqual(self.notify([{"subscriptionId": sub, "clientState": "wrong", "tenantId": TENANT}]).status_code, 202)
        self.conn.refresh_from_db()
        self.assertIsNone(self.conn.sync_requested_at)
        self.notify([{"subscriptionId": sub, "clientState": state, "tenantId": "other-tenant"}])
        self.conn.refresh_from_db()
        self.assertIsNone(self.conn.sync_requested_at)
        self.notify([{"subscriptionId": sub, "clientState": state, "tenantId": TENANT, "changeType": "updated"}])
        self.conn.refresh_from_db()
        first = self.conn.sync_requested_at
        self.assertIsNotNone(first)
        self.notify([{"subscriptionId": sub, "clientState": state, "tenantId": TENANT}])
        self.conn.refresh_from_db()
        self.assertEqual(self.conn.sync_requested_at, first, "a stream of changes must not postpone the sync")
        self.assertEqual(self.client.post("/api/entra/notify/", "nope", content_type="application/json").status_code, 400)

    def test_disabled_account_is_cut_off_on_the_next_tick(self):
        from datetime import timedelta

        from django.utils import timezone

        fake = FakeSubGraph({"staff": [user(1), user(2), user(3), user(4), user(5), user(6)]})
        with mock.patch.object(graph, "client_for", return_value=fake):
            self.assertEqual(sync.run_all(), 1)  # first sync + subscription
            self.conn.refresh_from_db()
            state = fake.created[0][1]
            # Not due yet: nothing runs.
            self.assertEqual(sync.run_all(), 0)
            fake.groups["staff"][0] = user(1, enabled=False)
            self.notify([{"subscriptionId": self.conn.subscription_id, "clientState": state, "tenantId": TENANT}])
            self.assertEqual(sync.run_all(), 0, "debounced for a few seconds")
            DirectoryConnection.objects.update(sync_requested_at=timezone.now() - timedelta(seconds=30))
            self.assertEqual(sync.run_all(), 1)
        self.assertFalse(Membership.objects.filter(account__email="user1@contoso.com", removed_at__isnull=True).exists())
        self.conn.refresh_from_db()
        self.assertIsNone(self.conn.sync_requested_at)

    def test_renew_recreate_and_remove(self):
        from datetime import timedelta

        from django.utils import timezone

        from . import notifications

        fake = FakeSubGraph({})
        self.subscribe(fake)
        self.assertEqual(notifications.ensure_subscription(self.conn, client=fake), "ok")
        later = timezone.now() + timedelta(days=6)
        self.assertEqual(notifications.ensure_subscription(self.conn, client=fake, now=later), "renewed")
        gone = FakeSubGraph({}, renew_status=404)
        self.assertEqual(notifications.ensure_subscription(self.conn, client=gone, now=later + timedelta(days=6)), "created")
        self.conn.status = "paused"
        self.conn.save()
        self.assertEqual(notifications.ensure_subscription(self.conn, client=gone), "removed")
        self.assertEqual(gone.deleted, ["sub-1"])
        self.assertEqual(self.conn.subscription_id, "")

    @override_settings(CLAVIUM_PUBLIC_URL="http://127.0.0.1:8000")
    def test_needs_a_public_https_address(self):
        from . import notifications

        self.assertIn("skipped", notifications.ensure_subscription(self.conn, client=FakeSubGraph({})))
        self.conn.refresh_from_db()
        self.assertEqual(self.conn.subscription_error, "no public https address")

    def test_disconnect_removes_the_subscription(self):
        fake = FakeSubGraph({})
        self.subscribe(fake)
        self.client.force_login(self.owner)
        with mock.patch.object(graph, "client_for", return_value=fake):
            self.client.post(f"/console/{self.org.id}/microsoft/action/", {"action": "disconnect"})
        self.assertEqual(fake.deleted, ["sub-1"])
