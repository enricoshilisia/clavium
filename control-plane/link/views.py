import time

from django.db import transaction
from django.utils import timezone
from rest_framework import serializers
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView

from accounts.models import Device, DeviceToken
from orgs.models import AuditLogEntry

from .models import LinkSession


def _ip(request):
    fwd = request.META.get("HTTP_X_FORWARDED_FOR", "")
    return fwd.split(",")[0].strip() if fwd else request.META.get("REMOTE_ADDR")


class StartSerializer(serializers.Serializer):
    public_key = serializers.RegexField(r"^[A-Za-z0-9_-]{43}$")
    client_device_id = serializers.CharField(max_length=64)
    name = serializers.CharField(max_length=200)
    platform = serializers.CharField(max_length=50, required=False, allow_blank=True)


class EnvelopeSerializer(serializers.Serializer):
    sender_public_key = serializers.RegexField(r"^[A-Za-z0-9_-]{43}$")
    nonce = serializers.RegexField(r"^[A-Za-z0-9_-]{16}$")
    ciphertext = serializers.RegexField(r"^[A-Za-z0-9_-]{40,400}$")


class StartView(APIView):
    """The new device opens a link session (no sign-in yet)."""

    permission_classes = [AllowAny]
    authentication_classes = []
    throttle_scope = "auth"

    def post(self, request):
        s = StartSerializer(data=request.data)
        s.is_valid(raise_exception=True)
        session, poll = LinkSession.start(requester_ip=_ip(request), **s.validated_data)
        return Response({"id": str(session.id), "poll_token": poll, "expires_in": 120}, status=201)


class PollView(APIView):
    """The new device waits. Once approved it receives, exactly once, its
    device token and the envelope; both are then wiped from the server."""

    permission_classes = [AllowAny]
    authentication_classes = []

    def get(self, request, link_id):
        token = request.query_params.get("poll_token", "")
        session = LinkSession.objects.filter(id=link_id).first()
        if session is None or not session.poll_token_ok(token):
            return Response({"detail": "unknown link"}, status=404)
        if request.query_params.get("wait") == "1":
            deadline = time.monotonic() + 25
            while session.status == LinkSession.Status.PENDING and not session.expired and time.monotonic() < deadline:
                time.sleep(1)
                session.refresh_from_db(fields=["status"])
        with transaction.atomic():
            session = LinkSession.objects.select_for_update().get(id=link_id)
            if session.status == LinkSession.Status.APPROVED:
                out = {
                    "status": "approved",
                    "token": session.raw_token,
                    "device_id": str(session.new_device_id),
                    "account": {"email": session.account.email},
                    "envelope": session.envelope,
                }
                session.status = LinkSession.Status.CLAIMED
                session.raw_token = ""
                session.envelope = None
                session.save(update_fields=["status", "raw_token", "envelope"])
                return Response(out)
        if session.status == LinkSession.Status.PENDING and session.expired:
            return Response({"status": "expired"})
        return Response({"status": session.status})


def _pending(link_id):
    session = LinkSession.objects.filter(id=link_id).first()
    if session is None or session.status != LinkSession.Status.PENDING or session.expired:
        return None
    return session


class InfoView(APIView):
    """What the approving phone shows before the person confirms."""

    def get(self, request, link_id):
        session = _pending(link_id)
        if session is None:
            return Response({"detail": "this QR code has expired. Show a new one on the other device."}, status=404)
        return Response(
            {
                "name": session.name,
                "platform": session.platform,
                "requester_ip": session.requester_ip,
                "public_key": session.public_key,
                "seconds_left": max(0, int(120 - (timezone.now() - session.created_at).total_seconds())),
            }
        )


class ApproveView(APIView):
    def post(self, request, link_id):
        env = EnvelopeSerializer(data=request.data.get("envelope") or {})
        env.is_valid(raise_exception=True)
        with transaction.atomic():
            session = LinkSession.objects.select_for_update().filter(id=link_id).first()
            if session is None or session.status != LinkSession.Status.PENDING or session.expired:
                return Response({"detail": "this QR code has expired. Show a new one on the other device."}, status=410)
            if request.data.get("public_key") != session.public_key:
                # The phone encrypted to the key in the QR it scanned; if
                # that is not the key this session registered, refuse.
                return Response({"detail": "QR code does not match this link"}, status=400)
            account = request.user
            device, _ = Device.objects.get_or_create(
                account=account,
                client_device_id=session.client_device_id,
                defaults={"name": session.name, "platform": session.platform},
            )
            if device.revoked_at is not None:
                device.revoked_at = None
                device.save(update_fields=["revoked_at"])
            device.tokens.filter(revoked_at__isnull=True).update(revoked_at=timezone.now())
            _, raw = DeviceToken.issue(device)
            session.status = LinkSession.Status.APPROVED
            session.account = account
            session.approved_by = request.auth
            session.new_device = device
            session.envelope = env.validated_data
            session.raw_token = raw
            session.save()
            AuditLogEntry.record(
                organization=None, actor=account, action="device.linked_by_qr", obj=device,
                approved_by_device=str(request.auth.pk), new_device=session.name, requester_ip=session.requester_ip,
            )
        return Response({"status": "approved", "device_id": str(device.id)})


class DenyView(APIView):
    def post(self, request, link_id):
        session = _pending(link_id)
        if session:
            session.status = LinkSession.Status.DENIED
            session.save(update_fields=["status"])
        return Response(status=204)
