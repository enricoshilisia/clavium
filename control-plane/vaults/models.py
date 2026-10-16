import uuid

from django.db import models

from accounts.models import Account, Device
from orgs.models import Organization


class VaultSnapshot(models.Model):
    """One encrypted upload of an account's vault file.

    `blob` is opaque to this server by design — it is exactly the bytes
    `Vault::seal()` produced, magic header and all. This process never
    decrypts it, never could (it holds no key), and only ever checks the
    four magic bytes as a cheap sanity check against an obviously wrong
    upload, not as a security boundary.
    """

    MAGIC = b"CLV1"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    account = models.ForeignKey(Account, related_name="vault_snapshots", on_delete=models.CASCADE)
    version = models.PositiveIntegerField()
    blob = models.BinaryField()
    sha256 = models.CharField(max_length=64)
    size_bytes = models.PositiveIntegerField()
    uploaded_by = models.ForeignKey(
        Device, related_name="uploaded_snapshots", null=True, on_delete=models.SET_NULL
    )
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=["account", "version"], name="unique_version_per_account")
        ]
        ordering = ["-version"]

    def __str__(self):
        return f"{self.account.email} v{self.version}"


class SharedVault(models.Model):
    """An organization-owned vault. Unlike a personal `VaultSnapshot`,
    there is no master password anywhere in this picture — the key that
    seals it is random, generated once, and exists only as the wrapped
    copies in `WrappedVaultKey` below. This server never has it.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    organization = models.ForeignKey(Organization, related_name="shared_vaults", on_delete=models.CASCADE)
    name = models.CharField(max_length=200)
    created_by = models.ForeignKey(Account, related_name="shared_vaults_created", on_delete=models.PROTECT)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.name} ({self.organization.name})"


class WrappedVaultKey(models.Model):
    """One device's own copy of a shared vault's key — RSA-OAEP ciphertext
    under that device's public key, produced client-side by
    `clavium_security_core::keypair::wrap_key_for_device`. This row is the
    entire access grant: a device with no row here has no way to even
    attempt opening the vault, and removing the row (offboarding, or a
    plain revoke) removes the grant completely and immediately.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    shared_vault = models.ForeignKey(SharedVault, related_name="wrapped_keys", on_delete=models.CASCADE)
    device = models.ForeignKey(Device, related_name="shared_vault_grants", on_delete=models.CASCADE)
    wrapped_key = models.BinaryField()
    granted_by = models.ForeignKey(
        Account, related_name="shared_vault_grants_made", null=True, on_delete=models.SET_NULL
    )
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=["shared_vault", "device"], name="unique_grant_per_device")
        ]

    def __str__(self):
        return f"{self.device.name} -> {self.shared_vault.name}"


class SharedVaultSnapshot(models.Model):
    """The same shape as a personal `VaultSnapshot` — opaque, versioned,
    checksummed — just keyed to a `SharedVault` instead of an `Account`.
    """

    MAGIC = b"CLV1"
    FORMAT_VERSION = 2  # raw-key sealing; see Vault::seal_with_raw_key

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    shared_vault = models.ForeignKey(SharedVault, related_name="snapshots", on_delete=models.CASCADE)
    version = models.PositiveIntegerField()
    blob = models.BinaryField()
    sha256 = models.CharField(max_length=64)
    size_bytes = models.PositiveIntegerField()
    uploaded_by = models.ForeignKey(
        Device, related_name="uploaded_shared_snapshots", null=True, on_delete=models.SET_NULL
    )
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["shared_vault", "version"], name="unique_version_per_shared_vault"
            )
        ]
        ordering = ["-version"]

    def __str__(self):
        return f"{self.shared_vault.name} v{self.version}"
