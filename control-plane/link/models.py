"""QR device linking. The server relays an envelope it cannot read
(see clavium_security_core::link) and issues the new device's token once
a signed-in device approves. Sessions live for two minutes."""

import hashlib
import secrets
import uuid
from datetime import timedelta

from django.db import models
from django.utils import timezone

from accounts.models import Account, Device

LIFETIME = timedelta(minutes=2)


def _h(raw: str) -> str:
    return hashlib.sha256(raw.encode()).hexdigest()


class LinkSession(models.Model):
    class Status(models.TextChoices):
        PENDING = "pending"
        APPROVED = "approved"
        CLAIMED = "claimed"
        DENIED = "denied"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    poll_token_hash = models.CharField(max_length=64)
    public_key = models.CharField(max_length=64)
    client_device_id = models.CharField(max_length=64)
    name = models.CharField(max_length=200)
    platform = models.CharField(max_length=50, blank=True)
    requester_ip = models.GenericIPAddressField(null=True, blank=True)
    status = models.CharField(max_length=10, choices=Status.choices, default=Status.PENDING)
    created_at = models.DateTimeField(auto_now_add=True)

    approved_by = models.ForeignKey(Device, null=True, blank=True, on_delete=models.SET_NULL, related_name="+")
    account = models.ForeignKey(Account, null=True, blank=True, on_delete=models.CASCADE, related_name="+")
    new_device = models.ForeignKey(Device, null=True, blank=True, on_delete=models.SET_NULL, related_name="+")
    # Held only between approval and the new device's next poll, then wiped.
    envelope = models.JSONField(null=True, blank=True)
    raw_token = models.CharField(max_length=128, blank=True)

    @classmethod
    def start(cls, **fields):
        raw = secrets.token_urlsafe(32)
        return cls.objects.create(poll_token_hash=_h(raw), **fields), raw

    def poll_token_ok(self, raw: str) -> bool:
        return secrets.compare_digest(self.poll_token_hash, _h(raw or ""))

    @property
    def expired(self) -> bool:
        return timezone.now() > self.created_at + LIFETIME
