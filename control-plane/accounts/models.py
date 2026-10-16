import hashlib
import secrets
import uuid

from django.contrib.auth.base_user import AbstractBaseUser, BaseUserManager
from django.contrib.auth.models import PermissionsMixin
from django.db import models


class AccountManager(BaseUserManager):
    """Accounts are identified by email; there is no separate username."""

    def create_user(self, email: str, password: str, **extra):
        if not email:
            raise ValueError("an account needs an email")
        account = self.model(email=self.normalize_email(email), **extra)
        account.set_password(password)
        account.save(using=self._db)
        return account

    def create_superuser(self, email: str, password: str, **extra):
        extra.setdefault("is_staff", True)
        extra.setdefault("is_superuser", True)
        return self.create_user(email, password, **extra)


class Account(AbstractBaseUser, PermissionsMixin):
    """A Clavium account.

    The password on this model authenticates to the control plane only —
    it is a completely different secret from any vault's master password,
    which this server never receives in any form. See PLAN.md's security
    model for why the two must never be conflated.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    email = models.EmailField(unique=True)
    display_name = models.CharField(max_length=200, blank=True)
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    objects = AccountManager()

    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = []

    def __str__(self):
        return self.email


def _generate_token() -> str:
    return secrets.token_urlsafe(32)


def _hash_token(raw: str) -> str:
    return hashlib.sha256(raw.encode()).hexdigest()


class Device(models.Model):
    """One instance of the desktop (or, later, mobile) app, registered to
    an account. A device is the unit of revocation: losing a laptop means
    revoking that one device's token, not changing the account password.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    account = models.ForeignKey(Account, related_name="devices", on_delete=models.CASCADE)
    # Client-generated and persisted locally, so re-registering the same
    # install reuses this row (and rotates its token) instead of piling up
    # a new device every time someone re-enters their password.
    client_device_id = models.CharField(max_length=64)
    name = models.CharField(max_length=200)
    platform = models.CharField(max_length=50, blank=True)
    # Base64 SPKI DER of this device's own RSA-2048 public key — the
    # asymmetric half of Milestone 3's shared-vault key hierarchy. Blank
    # until the device opts into an organization; the matching private
    # key never exists anywhere but on the device itself. A public key
    # cannot be rotated out from under a device's own standing grants, so
    # it is never updated in place — see `DeviceRegisterView`.
    public_key = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    last_seen_at = models.DateTimeField(null=True, blank=True)
    revoked_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["account", "client_device_id"], name="unique_device_per_account"
            )
        ]

    def __str__(self):
        return f"{self.name} ({self.account.email})"

    @property
    def is_revoked(self) -> bool:
        return self.revoked_at is not None


class DeviceToken(models.Model):
    """The bearer credential a device presents on every API call.

    Only the SHA-256 hash is stored — the same reasoning as any password
    at rest — so a stolen database does not hand out usable tokens.
    """

    device = models.ForeignKey(Device, related_name="tokens", on_delete=models.CASCADE)
    key_hash = models.CharField(max_length=64, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)
    revoked_at = models.DateTimeField(null=True, blank=True)

    @classmethod
    def issue(cls, device: Device) -> tuple["DeviceToken", str]:
        """A fresh token for `device`. Returns the raw key once — it is
        never recoverable after this, matching the master password's own
        "lost means lost" posture, because a recoverable bearer token
        would be a second, weaker way into the account.
        """
        raw = _generate_token()
        token = cls.objects.create(device=device, key_hash=_hash_token(raw))
        return token, raw

    @classmethod
    def authenticate(cls, raw: str) -> "DeviceToken | None":
        try:
            token = cls.objects.select_related("device", "device__account").get(
                key_hash=_hash_token(raw)
            )
        except cls.DoesNotExist:
            return None
        if token.revoked_at is not None or token.device.is_revoked:
            return None
        return token
