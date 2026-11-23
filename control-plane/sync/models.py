"""Per-record encrypted sync.

The server stores, per account, one keyring header (vault id + key slots,
no secrets) and one row per record: opaque ciphertext plus a revision. It
cannot read a record, and it never needs to: its only job is ordering
writes and refusing stale ones, so two devices can never silently
overwrite each other.
"""

import uuid

from django.db import models

from accounts.models import Account, Device


class SyncVault(models.Model):
    """One account's synced personal vault."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    account = models.OneToOneField(Account, related_name="sync_vault", on_delete=models.CASCADE)
    # The client's own vault id (from its keyring header). A device holding
    # a different vault cannot push into this one by accident.
    vault_id = models.UUIDField()
    keyring_header = models.JSONField()
    keyring_revision = models.PositiveIntegerField(default=1)
    # Monotonic per-account counter; every accepted item write takes the
    # next value. Pull cursors are positions in this sequence.
    counter = models.PositiveBigIntegerField(default=0)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.account.email} sync vault"


class SyncItem(models.Model):
    sync_vault = models.ForeignKey(SyncVault, related_name="items", on_delete=models.CASCADE)
    item_id = models.UUIDField()
    revision = models.PositiveBigIntegerField()
    deleted = models.BooleanField(default=False)
    nonce = models.CharField(max_length=32)
    ciphertext = models.TextField()
    size_bytes = models.PositiveIntegerField()
    updated_by = models.ForeignKey(Device, null=True, on_delete=models.SET_NULL, related_name="+")
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=["sync_vault", "item_id"], name="unique_item_per_sync_vault")
        ]
        indexes = [models.Index(fields=["sync_vault", "revision"], name="sync_item_rev_idx")]

    def as_wire(self):
        return {
            "id": str(self.item_id),
            "revision": self.revision,
            "deleted": self.deleted,
            "nonce": self.nonce,
            "ciphertext": self.ciphertext,
        }
