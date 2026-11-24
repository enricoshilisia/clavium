"""Share links. The server stores ciphertext it cannot read; the key is in
the link's #fragment, which never reaches the server. See
security-core/src/share.rs for the construction."""

from django.db import models
from django.utils import timezone

from accounts.models import Account


class Share(models.Model):
    MAX_FAILED = 5

    id = models.UUIDField(primary_key=True, editable=False)  # bound into the encryption by the app
    account = models.ForeignKey(Account, related_name="shares", on_delete=models.CASCADE)
    nonce = models.CharField(max_length=32, blank=True)
    ciphertext = models.TextField(blank=True)
    salt = models.CharField(max_length=32, blank=True)
    rounds = models.PositiveIntegerField(default=600_000)
    auth_hash = models.CharField(max_length=64)
    max_views = models.PositiveSmallIntegerField(default=1)
    views = models.PositiveSmallIntegerField(default=0)
    failed = models.PositiveSmallIntegerField(default=0)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    last_opened_at = models.DateTimeField(null=True, blank=True)
    revoked_at = models.DateTimeField(null=True, blank=True)
    wiped_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        indexes = [models.Index(fields=["account", "created_at"]), models.Index(fields=["expires_at"])]

    @property
    def status(self) -> str:
        if self.revoked_at:
            return "revoked"
        if self.failed >= self.MAX_FAILED:
            return "locked"
        if self.views >= self.max_views:
            return "used"
        if self.expires_at <= timezone.now():
            return "expired"
        return "active"

    @property
    def available(self) -> bool:
        return self.status == "active" and bool(self.ciphertext)

    def wipe(self, save=True):
        self.ciphertext = ""
        self.nonce = ""
        self.wiped_at = self.wiped_at or timezone.now()
        if save:
            self.save(update_fields=["ciphertext", "nonce", "wiped_at"])
