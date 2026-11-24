import base64
import hashlib
import hmac
import secrets
from datetime import timedelta

from django.conf import settings
from django.db import transaction
from django.shortcuts import render
from django.utils import timezone
from rest_framework import serializers
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView

from orgs.models import AuditLogEntry, OrgPolicy

from .models import Share

MAX_CIPHERTEXT = 96_000  # base64 of ~64 KB: one item, never a file dump
GONE = {"detail": "This link has expired, was already used, or was cancelled by the sender."}


def _b64(v, n=None, max_len=None, urlsafe=False):
    try:
        raw = base64.urlsafe_b64decode(v + "=" * (-len(v) % 4)) if urlsafe else base64.b64decode(v, validate=True)
    except Exception:
        raise serializers.ValidationError("not base64")
    if n is not None and len(raw) != n:
        raise serializers.ValidationError(f"must be {n} bytes")
    if max_len is not None and len(raw) > max_len:
        raise serializers.ValidationError("too long")
    return v


class CreateSerializer(serializers.Serializer):
    id = serializers.UUIDField()
    nonce = serializers.CharField(max_length=32)
    ciphertext = serializers.CharField(max_length=MAX_CIPHERTEXT)
    salt = serializers.CharField(max_length=32, allow_blank=True, default="")
    rounds = serializers.IntegerField(min_value=1000, max_value=5_000_000, default=600_000)
    auth_hash = serializers.RegexField(r"^[0-9a-f]{64}$")
    expires_in_hours = serializers.IntegerField(min_value=1, max_value=720, default=24)
    max_views = serializers.IntegerField(min_value=1, max_value=10, default=1)

    def validate_nonce(self, v):
        return _b64(v, 12)

    def validate_ciphertext(self, v):
        return _b64(v)

    def validate_salt(self, v):
        return _b64(v, 16) if v else v


def public_link(request, share_id) -> str:
    base = settings.CLAVIUM_PUBLIC_URL.rstrip("/") or request.build_absolute_uri("/").rstrip("/")
    return f"{base}/s/{share_id}"


def _row(s: Share):
    return {
        "id": str(s.id), "created_at": s.created_at, "expires_at": s.expires_at, "views": s.views,
        "max_views": s.max_views, "has_passphrase": bool(s.salt), "status": s.status, "last_opened_at": s.last_opened_at,
    }


class ShareListView(APIView):
    def get(self, request):
        rows = Share.objects.filter(account=request.user).order_by("-created_at")[:50]
        return Response([_row(s) for s in rows])

    def post(self, request):
        if not OrgPolicy.effective_for(request.user).get("allow_share_links", True):
            return Response({"detail": "Your organization has turned off share links."}, status=403)
        s = CreateSerializer(data=request.data)
        s.is_valid(raise_exception=True)
        d = s.validated_data
        if Share.objects.filter(id=d["id"]).exists():
            return Response({"detail": "that id is taken"}, status=409)
        share = Share.objects.create(
            id=d["id"], account=request.user, nonce=d["nonce"], ciphertext=d["ciphertext"], salt=d["salt"], rounds=d["rounds"],
            auth_hash=d["auth_hash"], max_views=d["max_views"], expires_at=timezone.now() + timedelta(hours=d["expires_in_hours"]),
        )
        # Not tied to an organization: the audit trail notes the act, never the content.
        AuditLogEntry.record(organization=None, actor=request.user, action="share.created", obj=share, max_views=share.max_views, hours=d["expires_in_hours"], passphrase=bool(share.salt))
        return Response({**_row(share), "url": public_link(request, share.id)}, status=201)


class ShareDetailView(APIView):
    def delete(self, request, share_id):
        share = Share.objects.filter(id=share_id, account=request.user).first()
        if share is None:
            return Response({"detail": "no such link"}, status=404)
        if not share.revoked_at:
            share.revoked_at = timezone.now()
            share.wipe(save=False)
            share.save(update_fields=["revoked_at", "ciphertext", "nonce", "wiped_at"])
            AuditLogEntry.record(organization=None, actor=request.user, action="share.revoked", obj=share)
        return Response(status=204)


class PublicView(APIView):
    permission_classes = [AllowAny]
    authentication_classes = []
    throttle_scope = "share"


class ShareMetaView(PublicView):
    """What the recipient's page needs before asking for anything. Does
    not count as a view."""

    def get(self, request, share_id):
        share = Share.objects.filter(id=share_id).first()
        if share is None or not share.available:
            return Response(GONE, status=410)
        return Response({
            "has_passphrase": bool(share.salt), "salt": share.salt, "rounds": share.rounds,
            "expires_at": share.expires_at, "views_left": share.max_views - share.views,
        })


class ShareOpenView(PublicView):
    """Hand out the ciphertext to whoever proves they hold the full key."""

    def post(self, request, share_id):
        auth = str(request.data.get("auth", ""))
        try:
            raw = base64.urlsafe_b64decode(auth + "=" * (-len(auth) % 4))
        except Exception:
            raw = b""
        with transaction.atomic():
            share = Share.objects.select_for_update().filter(id=share_id).first()
            if share is None or not share.available:
                return Response(GONE, status=410)
            if len(raw) != 32 or not hmac.compare_digest(hashlib.sha256(raw).hexdigest(), share.auth_hash):
                share.failed += 1
                if share.failed >= Share.MAX_FAILED:
                    share.wipe(save=False)
                share.save(update_fields=["failed", "ciphertext", "nonce", "wiped_at"])
                left = max(0, Share.MAX_FAILED - share.failed)
                msg = "Wrong passphrase." if share.salt else "This link is incomplete. Copy the whole link, including the part after #."
                if left == 0:
                    msg += " The link has now been locked."
                return Response({"detail": msg, "attempts_left": left}, status=403)
            share.views += 1
            share.last_opened_at = timezone.now()
            out = {"nonce": share.nonce, "ciphertext": share.ciphertext, "views_left": share.max_views - share.views}
            if share.views >= share.max_views:
                share.wipe(save=False)
            share.save(update_fields=["views", "last_opened_at", "ciphertext", "nonce", "wiped_at"])
        AuditLogEntry.record(organization=None, actor=None, action="share.opened", obj=share, views=share.views, owner=str(share.account_id))
        return Response(out)


def share_page(request, share_id):
    nonce = secrets.token_urlsafe(16)
    response = render(request, "shares/open.html", {"share_id": share_id, "nonce": nonce})
    response["Content-Security-Policy"] = (
        f"default-src 'none'; script-src 'nonce-{nonce}'; style-src 'nonce-{nonce}'; connect-src 'self'; "
        "img-src 'self' data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
    )
    response["Referrer-Policy"] = "no-referrer"
    response["Cache-Control"] = "no-store"
    response["X-Robots-Tag"] = "noindex, nofollow"
    return response
