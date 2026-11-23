import uuid

from django.core.cache import cache
from django.test import override_settings
from rest_framework.test import APITestCase

from accounts.models import Account, Device, DeviceToken
from orgs.models import AuditLogEntry


def header(vault_id, slots=1):
    return {
        "vault_id": str(vault_id),
        "slots": [{"id": str(uuid.uuid4()), "kind": "password", "nonce": "n", "wrapped_key": "w"}] * slots,
    }


def item(id_, revision=0, deleted=False, ct="Y2lwaGVy"):
    return {"id": str(id_), "revision": revision, "deleted": deleted, "nonce": "bm9uY2U=", "ciphertext": ct}


@override_settings(SECURE_SSL_REDIRECT=False)
class SyncTests(APITestCase):
    def setUp(self):
        cache.clear()
        self.account = Account.objects.create_user("a@example.com", "a long password 1")
        self.dev_a = self.client_for(self.account, "laptop")
        self.dev_b = self.client_for(self.account, "phone")
        self.vault_id = uuid.uuid4()

    def client_for(self, account, name):
        device = Device.objects.create(account=account, client_device_id=name, name=name)
        _, raw = DeviceToken.issue(device)
        client = self.client_class()
        client.credentials(HTTP_AUTHORIZATION=f"Bearer {raw}")
        return client

    def setup_keyring(self):
        r = self.dev_a.put(
            "/api/sync/keyring/",
            {"vault_id": str(self.vault_id), "header": header(self.vault_id), "base_revision": 0},
            format="json",
        )
        self.assertEqual(r.status_code, 200, r.content)
        return r.json()

    def push(self, client, items, vault_id=None):
        return client.post(
            "/api/sync/items/", {"vault_id": str(vault_id or self.vault_id), "items": items}, format="json"
        )

    def test_keyring_create_fetch_and_stale_update(self):
        self.assertEqual(self.dev_b.get("/api/sync/keyring/").status_code, 404)
        self.setup_keyring()
        got = self.dev_b.get("/api/sync/keyring/").json()
        self.assertEqual(got["revision"], 1)
        # b updates (e.g. new master password), then a's stale update is refused
        ok = self.dev_b.put(
            "/api/sync/keyring/",
            {"vault_id": str(self.vault_id), "header": header(self.vault_id, 2), "base_revision": 1},
            format="json",
        )
        self.assertEqual(ok.status_code, 200)
        stale = self.dev_a.put(
            "/api/sync/keyring/",
            {"vault_id": str(self.vault_id), "header": header(self.vault_id), "base_revision": 1},
            format="json",
        )
        self.assertEqual(stale.status_code, 409)
        self.assertEqual(stale.json()["current"]["revision"], 2)
        self.assertTrue(AuditLogEntry.objects.filter(action="sync.keyring_updated").exists())

    def test_a_different_vault_cannot_take_over(self):
        self.setup_keyring()
        other = uuid.uuid4()
        r = self.dev_b.put(
            "/api/sync/keyring/", {"vault_id": str(other), "header": header(other), "base_revision": 0}, format="json"
        )
        self.assertEqual(r.status_code, 409)
        self.assertEqual(self.push(self.dev_b, [item(uuid.uuid4())], vault_id=other).status_code, 409)

    def test_header_vault_id_must_match(self):
        r = self.dev_a.put(
            "/api/sync/keyring/",
            {"vault_id": str(self.vault_id), "header": header(uuid.uuid4()), "base_revision": 0},
            format="json",
        )
        self.assertEqual(r.status_code, 400)

    def test_push_pull_and_stale_push_is_a_conflict(self):
        self.setup_keyring()
        rid = uuid.uuid4()
        r = self.push(self.dev_a, [item(rid)]).json()
        self.assertEqual(r["results"][0], {"id": str(rid), "status": "accepted", "revision": 1})

        pulled = self.dev_b.get("/api/sync/items/?since=0").json()
        self.assertEqual(len(pulled["items"]), 1)
        self.assertEqual(pulled["cursor"], 1)

        # b edits based on rev 1 -> accepted as rev 2
        self.assertEqual(self.push(self.dev_b, [item(rid, 1, ct="YjI=")]).json()["results"][0]["revision"], 2)
        # a edits also based on rev 1 -> conflict, told the current revision
        res = self.push(self.dev_a, [item(rid, 1, ct="YTI=")]).json()["results"][0]
        self.assertEqual(res, {"id": str(rid), "status": "conflict", "revision": 2})
        # creating an item that already exists with base 0 is also a conflict
        self.assertEqual(self.push(self.dev_a, [item(rid, 0)]).json()["results"][0]["status"], "conflict")

        nothing_new = self.dev_a.get("/api/sync/items/?since=2").json()
        self.assertEqual(nothing_new["items"], [])
        self.assertEqual(nothing_new["cursor"], 2)

    def test_accounts_are_isolated(self):
        self.setup_keyring()
        self.push(self.dev_a, [item(uuid.uuid4())])
        other = Account.objects.create_user("b@example.com", "another long password")
        c = self.client_for(other, "x")
        self.assertEqual(c.get("/api/sync/items/?since=0").status_code, 404)
        self.assertEqual(c.get("/api/sync/keyring/").status_code, 404)

    def test_duplicate_ids_and_unauthenticated_are_refused(self):
        self.setup_keyring()
        rid = uuid.uuid4()
        self.assertEqual(self.push(self.dev_a, [item(rid), item(rid)]).status_code, 400)
        self.assertEqual(self.client.get("/api/sync/items/").status_code, 401)

    def test_reset_requires_the_account_password(self):
        self.setup_keyring()
        self.assertEqual(self.dev_a.post("/api/sync/reset/", {"password": "nope"}, format="json").status_code, 403)
        self.assertEqual(
            self.dev_a.post("/api/sync/reset/", {"password": "a long password 1"}, format="json").status_code, 204
        )
        self.assertEqual(self.dev_a.get("/api/sync/keyring/").status_code, 404)

    def test_pull_pages_with_has_more(self):
        from sync import views

        self.setup_keyring()
        old = views.MAX_PULL_ITEMS
        views.MAX_PULL_ITEMS = 2
        try:
            self.push(self.dev_a, [item(uuid.uuid4()) for _ in range(5)])
            first = self.dev_b.get("/api/sync/items/?since=0").json()
            self.assertTrue(first["has_more"])
            self.assertEqual(first["cursor"], 2)
            rest = []
            cursor = first["cursor"]
            while True:
                page = self.dev_b.get(f"/api/sync/items/?since={cursor}").json()
                rest += page["items"]
                cursor = page["cursor"]
                if not page["has_more"]:
                    break
            self.assertEqual(len(first["items"]) + len(rest), 5)
            self.assertEqual(cursor, 5)
        finally:
            views.MAX_PULL_ITEMS = old


@override_settings(SECURE_SSL_REDIRECT=False)
class ThrottleTests(APITestCase):
    def test_sign_in_attempts_are_rate_limited(self):
        cache.clear()
        Account.objects.create_user("t@example.com", "a long password 1")
        codes = []
        for _ in range(12):
            r = self.client.post(
                "/api/accounts/devices/register/",
                {"email": "t@example.com", "password": "wrong", "client_device_id": "x", "name": "x"},
                format="json",
            )
            codes.append(r.status_code)
        self.assertEqual(codes[-1], 429, codes)
