import base64
import os
import uuid

from django.core.cache import cache
from django.test import TestCase, override_settings
from rest_framework.test import APIClient

from accounts.models import Account, Device, DeviceToken
from orgs.models import Membership, Organization
from orgs.services import offboard

from .models import TeamAccess, TeamGroupRule, TeamItem, TeamVault
from .services import apply_group_rules

PW = "account password 1"


def b64(n):
    return base64.b64encode(os.urandom(n)).decode()


def wrapped():
    return {"ephemeral_public_key": b64(32), "nonce": b64(12), "ciphertext": b64(48)}


def item(i=None, rev=0, deleted=False):
    return {"id": str(i or uuid.uuid4()), "revision": rev, "deleted": deleted, "nonce": b64(12), "ciphertext": b64(80)}


@override_settings(SECURE_SSL_REDIRECT=False)
class TeamTests(TestCase):
    def setUp(self):
        cache.clear()
        self.owner_acct = Account.objects.create_user("owner@contoso.com", PW)
        self.org = Organization.objects.create(name="Contoso", created_by=self.owner_acct)
        Membership.objects.create(organization=self.org, account=self.owner_acct, role=Membership.Role.OWNER)
        self.owner = self.client_for(self.owner_acct)
        self.bob_acct, self.bob = self.member("bob@contoso.com")
        self.cat_acct, self.cat = self.member("cat@contoso.com")
        self.keys = {}
        for acct, c in ((self.owner_acct, self.owner), (self.bob_acct, self.bob), (self.cat_acct, self.cat)):
            self.set_key(acct, c)

    def client_for(self, acct):
        d = Device.objects.create(account=acct, client_device_id=str(uuid.uuid4()), name="Laptop")
        _, raw = DeviceToken.issue(d)
        c = APIClient()
        c.credentials(HTTP_AUTHORIZATION=f"Bearer {raw}")
        return c

    def member(self, email, role=Membership.Role.MEMBER):
        acct = Account.objects.create_user(email, PW)
        Membership.objects.create(organization=self.org, account=acct, role=role)
        return acct, self.client_for(acct)

    def set_key(self, acct, c):
        pk = b64(32)
        r = c.put("/api/teams/key/", {"public_key": pk, "encrypted_private_key": b64(60)}, format="json")
        self.assertEqual(r.status_code, 200, r.content)
        self.keys[acct.id] = pk
        return pk

    def create_team(self, name="Finance"):
        tid = str(uuid.uuid4())
        r = self.owner.post("/api/teams/", {"id": tid, "organization_id": str(self.org.id), "name": name, "wrapped_key": wrapped()}, format="json")
        self.assertEqual(r.status_code, 201, r.content)
        return tid

    def grant(self, tid, acct, by=None, kv=1):
        return (by or self.owner).post(
            f"/api/teams/{tid}/grants/",
            {"key_version": kv, "grants": [{"account_id": str(acct.id), "public_key": self.keys[acct.id], "wrapped_key": wrapped()}]},
            format="json",
        )

    def add(self, tid, acct, role="editor", with_key=True):
        body = {"account_id": str(acct.id), "role": role}
        if with_key:
            body.update(public_key=self.keys[acct.id], wrapped_key=wrapped(), key_version=1)
        return self.owner.post(f"/api/teams/{tid}/members/", body, format="json")

    def test_only_org_admins_create_and_creator_is_manager_with_key(self):
        r = self.bob.post("/api/teams/", {"id": str(uuid.uuid4()), "organization_id": str(self.org.id), "name": "X", "wrapped_key": wrapped()}, format="json")
        self.assertEqual(r.status_code, 403)
        tid = self.create_team()
        teams = self.owner.get("/api/teams/").json()["teams"]
        self.assertEqual((teams[0]["id"], teams[0]["role"], teams[0]["pending"]), (tid, "manager", False))
        self.assertIsNotNone(teams[0]["wrapped_key"])
        self.assertEqual(self.bob.get("/api/teams/").json()["teams"], [])

    def test_pending_member_gets_key_from_a_manager(self):
        tid = self.create_team()
        self.assertEqual(self.add(tid, self.bob_acct, with_key=False).status_code, 201)
        mine = self.bob.get("/api/teams/").json()["teams"][0]
        self.assertTrue(mine["pending"])
        self.assertIsNone(mine["wrapped_key"])
        self.assertEqual(self.bob.get(f"/api/teams/{tid}/items/").status_code, 403)
        members = self.owner.get(f"/api/teams/{tid}/members/").json()
        bob = next(m for m in members["members"] if m["email"] == "bob@contoso.com")
        self.assertEqual((bob["has_key"], bob["public_key"]), (False, self.keys[self.bob_acct.id]))
        self.assertIn("cat@contoso.com", [c["email"] for c in members["candidates"]])
        # Bob (editor) cannot grant; the manager can.
        self.assertEqual(self.grant(tid, self.bob_acct, by=self.bob).status_code, 403)
        self.assertEqual(self.grant(tid, self.bob_acct).json()["granted"], [str(self.bob_acct.id)])
        self.assertFalse(self.bob.get("/api/teams/").json()["teams"][0]["pending"])
        # Non-managers see members but not public keys or candidates.
        view = self.bob.get(f"/api/teams/{tid}/members/").json()
        self.assertNotIn("candidates", view)
        self.assertTrue(all(m["public_key"] is None for m in view["members"]))

    def test_grant_refuses_a_changed_key(self):
        tid = self.create_team()
        self.add(tid, self.bob_acct, with_key=False)
        stale = self.keys[self.bob_acct.id]
        self.set_key(self.bob_acct, self.bob)
        r = self.owner.post(f"/api/teams/{tid}/grants/", {"key_version": 1, "grants": [{"account_id": str(self.bob_acct.id), "public_key": stale, "wrapped_key": wrapped()}]}, format="json")
        self.assertEqual(r.json()["granted"], [])

    def test_new_account_key_makes_copies_pending(self):
        tid = self.create_team()
        self.add(tid, self.bob_acct)
        self.assertFalse(self.bob.get("/api/teams/").json()["teams"][0]["pending"])
        self.set_key(self.bob_acct, self.bob)
        self.assertTrue(self.bob.get("/api/teams/").json()["teams"][0]["pending"])

    def test_items_sync_and_roles(self):
        tid = self.create_team()
        self.add(tid, self.bob_acct, role="editor")
        self.add(tid, self.cat_acct, role="viewer")
        a = item()
        r = self.bob.post(f"/api/teams/{tid}/items/", {"key_version": 1, "items": [a]}, format="json")
        self.assertEqual(r.json()["results"][0]["status"], "ok")
        pulled = self.cat.get(f"/api/teams/{tid}/items/?since=0").json()
        self.assertEqual([i["id"] for i in pulled["items"]], [a["id"]])
        self.assertEqual(self.cat.post(f"/api/teams/{tid}/items/", {"key_version": 1, "items": [item()]}, format="json").status_code, 403)
        # Stale base revision is a conflict, stale key version is refused.
        r = self.owner.post(f"/api/teams/{tid}/items/", {"key_version": 1, "items": [{**a, "revision": 0}]}, format="json")
        self.assertEqual(r.json()["results"][0]["status"], "conflict")
        self.assertEqual(self.owner.post(f"/api/teams/{tid}/items/", {"key_version": 9, "items": []}, format="json").status_code, 409)
        # Outsiders see nothing.
        _, dan = self.member("dan@contoso.com")
        self.assertEqual(dan.get(f"/api/teams/{tid}/items/").status_code, 403)

    def test_removal_requires_rotation_and_rotation_replaces_everything(self):
        tid = self.create_team()
        self.add(tid, self.bob_acct)
        self.add(tid, self.cat_acct)
        self.bob.post(f"/api/teams/{tid}/items/", {"key_version": 1, "items": [item(), item()]}, format="json")
        self.assertEqual(self.owner.delete(f"/api/teams/{tid}/members/{self.cat_acct.id}/").status_code, 204)
        self.assertTrue(TeamVault.objects.get(id=tid).needs_rotation)
        self.assertEqual(self.cat.get(f"/api/teams/{tid}/items/").status_code, 403)
        new_items = [item(), item()]
        grants = [{"account_id": str(a.id), "public_key": self.keys[a.id], "wrapped_key": wrapped()} for a in (self.owner_acct,)]
        # Editors cannot rotate; wrong version refused; must include self.
        self.assertEqual(self.bob.post(f"/api/teams/{tid}/rotate/", {"key_version": 2, "items": new_items, "grants": grants}, format="json").status_code, 403)
        self.assertEqual(self.owner.post(f"/api/teams/{tid}/rotate/", {"key_version": 3, "items": new_items, "grants": grants}, format="json").status_code, 409)
        r = self.owner.post(f"/api/teams/{tid}/rotate/", {"key_version": 2, "items": new_items, "grants": grants}, format="json")
        self.assertEqual(r.status_code, 200, r.content)
        team = TeamVault.objects.get(id=tid)
        self.assertEqual((team.key_version, team.needs_rotation), (2, False))
        self.assertEqual(set(TeamItem.objects.filter(team=team).values_list("item_id", flat=True)), {uuid.UUID(i["id"]) for i in new_items})
        # Bob got no copy of the new key in this rotation: pending until granted.
        self.assertTrue(self.bob.get("/api/teams/").json()["teams"][0]["pending"])
        self.assertEqual(self.grant(tid, self.bob_acct, kv=2).json()["granted"], [str(self.bob_acct.id)])
        self.assertEqual(len(self.bob.get(f"/api/teams/{tid}/items/?since=0").json()["items"]), 2)

    def test_leaving_the_org_removes_team_access(self):
        tid = self.create_team()
        self.add(tid, self.bob_acct)
        m = Membership.objects.get(account=self.bob_acct)
        offboard(self.org, m, self.owner_acct, revoke_devices=False)
        self.assertFalse(TeamAccess.objects.filter(account=self.bob_acct).exists())
        self.assertTrue(TeamVault.objects.get(id=tid).needs_rotation)

    def test_last_manager_is_protected_and_people_can_leave(self):
        tid = self.create_team()
        self.add(tid, self.bob_acct)
        self.assertEqual(self.owner.patch(f"/api/teams/{tid}/members/{self.owner_acct.id}/", {"role": "editor"}, format="json").status_code, 409)
        self.assertEqual(self.owner.delete(f"/api/teams/{tid}/members/{self.owner_acct.id}/").status_code, 409)
        self.assertEqual(self.bob.delete(f"/api/teams/{tid}/members/{self.bob_acct.id}/").status_code, 204)

    def test_org_admin_outside_the_team_can_manage_but_not_read(self):
        tid = self.create_team()
        admin_acct, admin = self.member("it@contoso.com", role=Membership.Role.ADMIN)
        listed = admin.get("/api/teams/").json()["teams"][0]
        self.assertEqual((listed["role"], listed["can_manage"], listed["wrapped_key"]), (None, True, None))
        self.assertEqual(admin.get(f"/api/teams/{tid}/items/").status_code, 403)
        r = admin.post(f"/api/teams/{tid}/members/", {"account_id": str(self.bob_acct.id), "role": "viewer"}, format="json")
        self.assertEqual(r.json()["has_key"], False)

    def test_group_rules_add_and_remove_access(self):
        tid = self.create_team()
        team = TeamVault.objects.get(id=tid)
        TeamGroupRule.objects.create(team=team, group_id="g-fin", group_name="Finance", role="viewer")
        Membership.objects.filter(account=self.bob_acct).update(entra_groups=["g-fin"])
        self.assertEqual(apply_group_rules(self.org)["added"], 1)
        a = TeamAccess.objects.get(team=team, account=self.bob_acct)
        self.assertEqual((a.role, a.source, a.wrapped_key), ("viewer", "group", None))
        self.grant(tid, self.bob_acct)
        Membership.objects.filter(account=self.bob_acct).update(entra_groups=[])
        self.assertEqual(apply_group_rules(self.org)["removed"], 1)
        self.assertTrue(TeamVault.objects.get(id=tid).needs_rotation)
        # Hand-added access is never touched by rules.
        self.add(tid, self.cat_acct)
        apply_group_rules(self.org)
        self.assertTrue(TeamAccess.objects.filter(team=team, account=self.cat_acct).exists())

    def test_rejects_malformed_keys(self):
        r = self.bob.put("/api/teams/key/", {"public_key": "short", "encrypted_private_key": b64(60)}, format="json")
        self.assertEqual(r.status_code, 400)
        bad = {**wrapped(), "ciphertext": b64(10)}
        r = self.owner.post("/api/teams/", {"id": str(uuid.uuid4()), "organization_id": str(self.org.id), "name": "X", "wrapped_key": bad}, format="json")
        self.assertEqual(r.status_code, 400)
