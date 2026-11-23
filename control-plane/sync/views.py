import time

from django.db import transaction
from rest_framework import serializers
from rest_framework.response import Response
from rest_framework.views import APIView

from orgs.models import AuditLogEntry

from .models import SyncItem, SyncVault

MAX_PUSH_ITEMS = 500
MAX_PULL_ITEMS = 1000
MAX_ITEM_BYTES = 1_000_000
MAX_HEADER_BYTES = 256_000
LONG_POLL_SECONDS = 25


class KeyringSerializer(serializers.Serializer):
    vault_id = serializers.UUIDField()
    header = serializers.JSONField()
    base_revision = serializers.IntegerField(min_value=0)

    def validate_header(self, value):
        import json

        if not isinstance(value, dict) or not isinstance(value.get("slots"), list):
            raise serializers.ValidationError("header must be a keyring header object")
        if not value["slots"]:
            raise serializers.ValidationError("a keyring needs at least one key slot")
        if len(json.dumps(value)) > MAX_HEADER_BYTES:
            raise serializers.ValidationError("header too large")
        return value

    def validate(self, data):
        if str(data["header"].get("vault_id")) != str(data["vault_id"]):
            raise serializers.ValidationError("vault_id does not match the header")
        return data


class ItemSerializer(serializers.Serializer):
    id = serializers.UUIDField()
    revision = serializers.IntegerField(min_value=0)
    deleted = serializers.BooleanField()
    nonce = serializers.CharField(max_length=32)
    ciphertext = serializers.CharField(max_length=MAX_ITEM_BYTES * 2)


class PushSerializer(serializers.Serializer):
    vault_id = serializers.UUIDField()
    items = ItemSerializer(many=True, allow_empty=True)

    def validate_items(self, value):
        if len(value) > MAX_PUSH_ITEMS:
            raise serializers.ValidationError(f"at most {MAX_PUSH_ITEMS} items per push")
        ids = [i["id"] for i in value]
        if len(ids) != len(set(ids)):
            raise serializers.ValidationError("duplicate item ids in one push")
        return value


def _keyring_payload(sv: SyncVault):
    return {
        "vault_id": str(sv.vault_id),
        "header": sv.keyring_header,
        "revision": sv.keyring_revision,
        "counter": sv.counter,
    }


class KeyringView(APIView):
    """GET: the keyring a new device needs to unlock. PUT: create it (first
    device, base_revision 0) or replace it after a master-password change
    or a new passkey/recovery slot (base_revision = the one it read)."""

    def get(self, request):
        sv = SyncVault.objects.filter(account=request.user).first()
        if sv is None:
            return Response({"detail": "sync has not been set up for this account"}, status=404)
        return Response(_keyring_payload(sv))

    def put(self, request):
        s = KeyringSerializer(data=request.data)
        s.is_valid(raise_exception=True)
        data = s.validated_data
        with transaction.atomic():
            sv = SyncVault.objects.select_for_update().filter(account=request.user).first()
            if sv is None:
                if data["base_revision"] != 0:
                    return Response({"detail": "no keyring exists yet; use base_revision 0"}, status=409)
                sv = SyncVault.objects.create(
                    account=request.user,
                    vault_id=data["vault_id"],
                    keyring_header=data["header"],
                )
                action = "sync.keyring_created"
            else:
                if sv.vault_id != data["vault_id"]:
                    return Response(
                        {
                            "detail": "this account already syncs a different vault",
                            "current": _keyring_payload(sv),
                        },
                        status=409,
                    )
                if sv.keyring_revision != data["base_revision"]:
                    return Response(
                        {"detail": "keyring changed on another device", "current": _keyring_payload(sv)},
                        status=409,
                    )
                sv.keyring_header = data["header"]
                sv.keyring_revision += 1
                sv.save(update_fields=["keyring_header", "keyring_revision", "updated_at"])
                action = "sync.keyring_updated"
            AuditLogEntry.record(
                organization=None,
                actor=request.user,
                action=action,
                obj=sv,
                device=str(request.auth.pk),
                slots=len(data["header"]["slots"]),
            )
        return Response(_keyring_payload(sv))


class ItemsView(APIView):
    """GET ?since=N: every item with revision > N, oldest first.
    GET ?since=N&wait=1: long-poll up to 25s for a change (live sync).
    POST: push changes; each is accepted only if its base revision is
    still the server's current one, else reported as a conflict."""

    def get(self, request):
        try:
            since = int(request.query_params.get("since", "0"))
        except ValueError:
            return Response({"detail": "since must be an integer"}, status=400)
        sv = SyncVault.objects.filter(account=request.user).first()
        if sv is None:
            return Response({"detail": "sync has not been set up for this account"}, status=404)

        if request.query_params.get("wait") == "1":
            deadline = time.monotonic() + LONG_POLL_SECONDS
            while sv.counter <= since and time.monotonic() < deadline:
                time.sleep(1)
                sv.refresh_from_db(fields=["counter", "keyring_revision"])

        rows = list(
            SyncItem.objects.filter(sync_vault=sv, revision__gt=since).order_by("revision")[: MAX_PULL_ITEMS + 1]
        )
        has_more = len(rows) > MAX_PULL_ITEMS
        rows = rows[:MAX_PULL_ITEMS]
        cursor = rows[-1].revision if has_more else max(sv.counter, since)
        return Response(
            {
                "items": [r.as_wire() for r in rows],
                "cursor": cursor,
                "has_more": has_more,
                "keyring_revision": sv.keyring_revision,
            }
        )

    def post(self, request):
        s = PushSerializer(data=request.data)
        s.is_valid(raise_exception=True)
        data = s.validated_data
        results = []
        with transaction.atomic():
            sv = SyncVault.objects.select_for_update().filter(account=request.user).first()
            if sv is None:
                return Response({"detail": "upload a keyring before pushing items"}, status=409)
            if sv.vault_id != data["vault_id"]:
                return Response({"detail": "this account syncs a different vault"}, status=409)
            existing = {
                row.item_id: row
                for row in SyncItem.objects.filter(sync_vault=sv, item_id__in=[i["id"] for i in data["items"]])
            }
            for item in data["items"]:
                size = len(item["ciphertext"])
                if size > MAX_ITEM_BYTES * 4 // 3 + 4:
                    results.append({"id": str(item["id"]), "status": "rejected", "detail": "item too large"})
                    continue
                row = existing.get(item["id"])
                current = row.revision if row else 0
                if item["revision"] != current:
                    results.append(
                        {
                            "id": str(item["id"]),
                            "status": "conflict",
                            "revision": current,
                        }
                    )
                    continue
                sv.counter += 1
                if row is None:
                    row = SyncItem(sync_vault=sv, item_id=item["id"])
                row.revision = sv.counter
                row.deleted = item["deleted"]
                row.nonce = item["nonce"]
                row.ciphertext = item["ciphertext"]
                row.size_bytes = size
                row.updated_by = request.auth
                row.save()
                results.append({"id": str(item["id"]), "status": "accepted", "revision": sv.counter})
            sv.save(update_fields=["counter", "updated_at"])
        return Response({"results": results, "counter": sv.counter})


class ResetView(APIView):
    """Delete this account's synced vault entirely (keyring and items), so
    a different local vault can be linked. Requires the account password
    again: it is destructive and cannot be undone server-side."""

    def post(self, request):
        password = request.data.get("password", "")
        if not request.user.check_password(password):
            return Response({"detail": "account password is incorrect"}, status=403)
        sv = SyncVault.objects.filter(account=request.user).first()
        if sv is None:
            return Response(status=204)
        AuditLogEntry.record(
            organization=None, actor=request.user, action="sync.reset", obj=sv, device=str(request.auth.pk)
        )
        sv.delete()
        return Response(status=204)
