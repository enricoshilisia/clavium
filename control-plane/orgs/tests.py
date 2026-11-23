import base64
import uuid

from django.core.cache import cache
from django.test import TestCase, override_settings
from rest_framework.test import APIClient

from accounts.models import Account, Device, DeviceToken
from orgs.models import AuditLogEntry, HealthSnapshot, Invite, Membership, Organization, OrgPolicy, ScimToken
from vaults.models import SharedVault, WrappedVaultKey

SHARED_BLOB = base64.b64encode(b"CLV1" + bytes([2]) + b"\x00" * 40).decode()


def device_client(account, name="laptop"):
    d = Device.objects.create(account=account, client_device_id=name + str(uuid.uuid4()), name=name)
    _, raw = DeviceToken.issue(d)
    c = APIClient()
    c.credentials(HTTP_AUTHORIZATION=f"Bearer {raw}")
    return c, d


@override_settings(SECURE_SSL_REDIRECT=False)
class Base(TestCase):
    def setUp(self):
        cache.clear()
        self.owner = Account.objects.create_user("owner@acme.test", "owner password 1")
        self.alice = Account.objects.create_user("alice@acme.test", "alice password 1")
        self.org = Organization.objects.create(name="Acme", created_by=self.owner)
        self.om = Membership.objects.create(organization=self.org, account=self.owner, role="owner")
        self.am = Membership.objects.create(organization=self.org, account=self.alice, role="member")
        self.oc, self.od = device_client(self.owner)
        self.ac, self.ad = device_client(self.alice)


class PolicyAndHealthTests(Base):
    def test_effective_policy_is_the_strictest(self):
        other = Organization.objects.create(name="Other", created_by=self.owner)
        Membership.objects.create(organization=other, account=self.alice, role="member")
        OrgPolicy.objects.create(organization=self.org, min_master_password_length=14, max_auto_lock_minutes=30, allow_export=True)
        OrgPolicy.objects.create(organization=other, min_master_password_length=12, max_auto_lock_minutes=5, allow_export=False)
        p = self.ac.get("/api/orgs/policy/mine/").json()
        self.assertEqual(p["min_master_password_length"], 14)
        self.assertEqual(p["max_auto_lock_minutes"], 5)
        self.assertFalse(p["allow_export"])
        self.assertEqual(sorted(p["organizations"]), ["Acme", "Other"])

    def test_only_admins_set_policy(self):
        r = self.ac.put(f"/api/orgs/{self.org.id}/policy/", {"min_master_password_length": 20}, format="json")
        self.assertEqual(r.status_code, 403)
        r = self.oc.put(f"/api/orgs/{self.org.id}/policy/", {"min_master_password_length": 16, "allow_export": False}, format="json")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()["min_master_password_length"], 16)
        self.assertEqual(self.oc.put(f"/api/orgs/{self.org.id}/policy/", {"min_master_password_length": 3}, format="json").status_code, 400)
        self.assertTrue(AuditLogEntry.objects.filter(action="policy.updated").exists())

    def test_health_report_is_counts_only(self):
        body = {"score": 72, "total": 40, "weak": 3, "reused": 4, "old": 1, "without_totp": 20, "has_recovery_key": True}
        self.assertEqual(self.ac.post("/api/orgs/health/", body, format="json").status_code, 204)
        h = HealthSnapshot.objects.get(account=self.alice)
        self.assertEqual((h.score, h.weak), (72, 3))
        self.assertEqual(self.ac.post("/api/orgs/health/", {**body, "score": 101}, format="json").status_code, 400)
        self.assertEqual(self.ac.post("/api/orgs/health/", {**body, "weak": "lots"}, format="json").status_code, 400)


class ScimTests(Base):
    def setUp(self):
        super().setUp()
        _, raw = ScimToken.issue(self.org, self.owner, "Entra ID")
        self.scim = APIClient()
        self.scim.credentials(HTTP_AUTHORIZATION=f"Bearer {raw}")

    def create(self, email, ext="ext-1"):
        return self.scim.post(
            "/scim/v2/Users",
            {
                "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
                "userName": email,
                "externalId": ext,
                "active": True,
                "name": {"givenName": "Bob", "familyName": "Otieno"},
                "emails": [{"primary": True, "type": "work", "value": email}],
            },
            format="json",
        )

    def test_bad_token_is_refused(self):
        c = APIClient()
        c.credentials(HTTP_AUTHORIZATION="Bearer nope")
        self.assertEqual(c.get("/scim/v2/Users").status_code, 401)
        self.assertEqual(self.scim.get("/scim/v2/ServiceProviderConfig").status_code, 200)

    def test_provision_filter_deactivate_reactivate_delete(self):
        r = self.create("bob@acme.test")
        self.assertEqual(r.status_code, 201, r.content)
        user = r.json()
        self.assertEqual(user["userName"], "bob@acme.test")
        self.assertIn("/console/invite/", user["urn:clavium:invite"]["url"])
        bob = Account.objects.get(email="bob@acme.test")
        self.assertFalse(bob.has_usable_password())
        self.assertEqual(self.create("bob@acme.test").status_code, 409)

        found = self.scim.get('/scim/v2/Users?filter=userName eq "bob@acme.test"').json()
        self.assertEqual(found["totalResults"], 1)
        self.assertEqual(self.scim.get('/scim/v2/Users?filter=externalId eq "ext-1"').json()["totalResults"], 1)

        # Bob signs in on a device, gets a shared vault grant.
        bob.set_password("bob password 12")
        bob.save()
        bc, bd = device_client(bob, "bob-phone")
        sv = SharedVault.objects.create(organization=self.org, name="Ops", created_by=self.owner)
        WrappedVaultKey.objects.create(shared_vault=sv, device=bd, wrapped_key=b"x")

        # Entra deactivates with a string boolean and capitalised op.
        patch = {"schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"], "Operations": [{"op": "Replace", "path": "active", "value": "False"}]}
        r = self.scim.patch(f"/scim/v2/Users/{user['id']}", patch, format="json")
        self.assertEqual(r.status_code, 200)
        self.assertFalse(r.json()["active"])
        self.assertEqual(bc.get("/api/sync/keyring/").status_code, 401, "device signed out")
        self.assertFalse(WrappedVaultKey.objects.filter(device=bd).exists())
        sv.refresh_from_db()
        self.assertTrue(sv.needs_rotation)
        bob.refresh_from_db()
        self.assertFalse(bob.is_active)

        patch["Operations"][0]["value"] = "True"
        self.assertTrue(self.scim.patch(f"/scim/v2/Users/{user['id']}", patch, format="json").json()["active"])
        bob.refresh_from_db()
        self.assertTrue(bob.is_active)

        self.assertEqual(self.scim.delete(f"/scim/v2/Users/{user['id']}").status_code, 204)
        self.assertIsNotNone(Membership.objects.get(id=user["id"]).removed_at)
        self.assertTrue(AuditLogEntry.objects.filter(action="member.provisioned").exists())

    def test_tokens_only_see_their_own_org(self):
        other = Organization.objects.create(name="Other", created_by=self.owner)
        _, raw = ScimToken.issue(other, self.owner)
        c = APIClient()
        c.credentials(HTTP_AUTHORIZATION=f"Bearer {raw}")
        self.assertEqual(c.get(f"/scim/v2/Users/{self.am.id}").status_code, 404)
        self.assertEqual(c.get("/scim/v2/Users").json()["totalResults"], 0)


class RotationTests(Base):
    def test_removed_member_forces_rotation_before_new_writes(self):
        sv = SharedVault.objects.create(organization=self.org, name="Ops", created_by=self.owner)
        WrappedVaultKey.objects.create(shared_vault=sv, device=self.od, wrapped_key=b"o")
        WrappedVaultKey.objects.create(shared_vault=sv, device=self.ad, wrapped_key=b"a")
        url = f"/api/orgs/{self.org.id}/shared-vaults/{sv.id}"
        self.assertEqual(self.oc.post(f"{url}/snapshots/", {"blob": SHARED_BLOB, "key_version": 1}, format="json").status_code, 201)

        r = self.oc.post(f"/api/orgs/{self.org.id}/members/{self.am.id}/remove/", {"revoke_devices": True}, format="json")
        self.assertEqual(r.json()["vaults_needing_rotation"], 1)
        self.assertEqual(self.oc.post(f"{url}/snapshots/", {"blob": SHARED_BLOB, "key_version": 1}, format="json").status_code, 409)

        # Only admins rotate; key_version must be current + 1.
        self.assertEqual(self.ac.post(f"{url}/rotate/", {}, format="json").status_code, 401)
        bad = self.oc.post(f"{url}/rotate/", {"key_version": 5, "blob": SHARED_BLOB, "grants": [{"device_id": str(self.od.id), "wrapped_key": "bmV3"}]}, format="json")
        self.assertEqual(bad.status_code, 409)
        # A removed member's device cannot be re-granted in the rotation.
        bad = self.oc.post(f"{url}/rotate/", {"key_version": 2, "blob": SHARED_BLOB, "grants": [{"device_id": str(self.ad.id), "wrapped_key": "bmV3"}]}, format="json")
        self.assertEqual(bad.status_code, 400)
        ok = self.oc.post(f"{url}/rotate/", {"key_version": 2, "blob": SHARED_BLOB, "grants": [{"device_id": str(self.od.id), "wrapped_key": "bmV3"}]}, format="json")
        self.assertEqual(ok.status_code, 200, ok.content)
        sv.refresh_from_db()
        self.assertEqual((sv.key_version, sv.needs_rotation), (2, False))
        self.assertEqual(list(sv.wrapped_keys.values_list("wrapped_key", flat=True)), [b"new"])
        self.assertEqual(self.oc.post(f"{url}/snapshots/", {"blob": SHARED_BLOB, "key_version": 1}, format="json").status_code, 409)
        self.assertEqual(self.oc.post(f"{url}/snapshots/", {"blob": SHARED_BLOB, "key_version": 2}, format="json").status_code, 201)


@override_settings(SECURE_SSL_REDIRECT=False)
class ConsoleTests(TestCase):
    def setUp(self):
        cache.clear()
        self.owner = Account.objects.create_user("owner@acme.test", "owner password 1")
        self.member = Account.objects.create_user("m@acme.test", "member password 1")

    def login(self, email="owner@acme.test", pw="owner password 1"):
        return self.client.post("/console/login/", {"email": email, "password": pw})

    def test_login_create_org_add_invite_accept_policy_remove(self):
        self.assertEqual(self.client.get("/console/").status_code, 302)
        self.assertEqual(self.login(pw="wrong").status_code, 401)
        self.assertEqual(self.login().status_code, 302)
        r = self.client.post("/console/new/", {"name": "Acme"})
        org = Organization.objects.get(name="Acme")
        self.assertRedirects(r, f"/console/{org.id}/")
        page = self.client.get(f"/console/{org.id}/")
        self.assertContains(page, "Acme")
        act = f"/console/{org.id}/action/"

        # Add an existing account and a brand-new one (gets an invite link).
        self.client.post(act, {"action": "add_member", "email": "m@acme.test", "role": "member"})
        self.client.post(act, {"action": "add_member", "email": "new@acme.test", "role": "member"})
        page = self.client.get(f"/console/{org.id}/")
        self.assertContains(page, "Invite link for new@acme.test")
        invite_url = page.context["new_secret"]["value"]
        token = invite_url.rstrip("/").split("/")[-1]

        # The invite sets the account password, once.
        c2 = self.client_class()
        self.assertContains(c2.get(f"/console/invite/{token}/"), "Join Acme")
        self.assertContains(c2.post(f"/console/invite/{token}/", {"password": "brand new pass 1", "password2": "brand new pass 1"}), "You are set up")
        self.assertTrue(Account.objects.get(email="new@acme.test").check_password("brand new pass 1"))
        self.assertEqual(c2.get(f"/console/invite/{token}/").status_code, 404)

        # Policy
        self.client.post(act, {"action": "policy", "min_master_password_length": "16", "max_auto_lock_minutes": "5", "require_recovery_key": "on"})
        p = OrgPolicy.objects.get(organization=org)
        self.assertEqual((p.min_master_password_length, p.max_auto_lock_minutes, p.allow_export, p.require_recovery_key), (16, 5, False, True))

        # Remove with sign-out
        d = Device.objects.create(account=self.member, client_device_id="x", name="phone")
        DeviceToken.issue(d)
        m = Membership.objects.get(organization=org, account=self.member)
        self.client.post(act, {"action": "remove_member", "membership_id": m.id, "revoke_devices": "on"})
        d.refresh_from_db()
        self.assertIsNotNone(d.revoked_at)
        m.refresh_from_db()
        self.assertIsNotNone(m.removed_at)

        # SCIM token shown once
        self.client.post(act, {"action": "scim_create", "label": "Entra"})
        secret = self.client.get(f"/console/{org.id}/").context["new_secret"]["value"]
        self.assertTrue(secret.startswith("scim_"))
        self.assertIsNotNone(ScimToken.authenticate(secret))

    def test_members_cannot_use_the_console_for_an_org(self):
        org = Organization.objects.create(name="Acme", created_by=self.owner)
        Membership.objects.create(organization=org, account=self.owner, role="owner")
        Membership.objects.create(organization=org, account=self.member, role="member")
        self.login("m@acme.test", "member password 1")
        self.assertEqual(self.client.get(f"/console/{org.id}/").status_code, 403)
        self.assertEqual(self.client.post(f"/console/{org.id}/action/", {"action": "policy"}).status_code, 403)

    def test_last_owner_cannot_be_removed_or_demoted(self):
        self.login()
        self.client.post("/console/new/", {"name": "Solo"})
        org = Organization.objects.get(name="Solo")
        m = Membership.objects.get(organization=org, account=self.owner)
        self.client.post(f"/console/{org.id}/action/", {"action": "remove_member", "membership_id": m.id})
        self.client.post(f"/console/{org.id}/action/", {"action": "change_role", "membership_id": m.id, "role": "member"})
        m.refresh_from_db()
        self.assertIsNone(m.removed_at)
        self.assertEqual(m.role, "owner")
