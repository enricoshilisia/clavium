"""Team vaults: shared, end-to-end encrypted vaults inside an organization.

The server stores only public keys, sealed copies of each team key (one
per member, openable only with that member's private key), and per-item
ciphertext. See security-core/src/team.rs for the cryptography.
"""

import uuid

from django.db import models

from accounts.models import Account
from orgs.models import Organization


class AccountKey(models.Model):
    """An account's X25519 public key, plus its private key encrypted
    with the account's personal vault key (useless to this server)."""

    account = models.OneToOneField(Account, related_name="team_key", on_delete=models.CASCADE)
    public_key = models.CharField(max_length=64)
    encrypted_private_key = models.TextField()
    updated_at = models.DateTimeField(auto_now=True)


class TeamVault(models.Model):
    # Chosen by the creating client: the id is bound into every item's
    # encryption, so it must exist before anything is encrypted.
    id = models.UUIDField(primary_key=True, editable=False)
    organization = models.ForeignKey(Organization, related_name="team_vaults", on_delete=models.CASCADE)
    name = models.CharField(max_length=200)
    created_by = models.ForeignKey(Account, null=True, on_delete=models.SET_NULL, related_name="+")
    created_at = models.DateTimeField(auto_now_add=True)
    key_version = models.PositiveIntegerField(default=1)
    # Someone who held the key lost access; a manager's app replaces the
    # key (and re-encrypts) the next time it syncs.
    needs_rotation = models.BooleanField(default=False)
    counter = models.PositiveBigIntegerField(default=0)

    def __str__(self):
        return f"{self.name} ({self.organization.name})"


class TeamAccess(models.Model):
    class Role(models.TextChoices):
        MANAGER = "manager", "Manager"
        EDITOR = "editor", "Can edit"
        VIEWER = "viewer", "Can view"

    class Source(models.TextChoices):
        MANUAL = "manual", "Added by hand"
        GROUP = "group", "Microsoft 365 group"

    RANK = {Role.VIEWER: 1, Role.EDITOR: 2, Role.MANAGER: 3}

    team = models.ForeignKey(TeamVault, related_name="accesses", on_delete=models.CASCADE)
    account = models.ForeignKey(Account, related_name="team_accesses", on_delete=models.CASCADE)
    role = models.CharField(max_length=10, choices=Role.choices, default=Role.EDITOR)
    source = models.CharField(max_length=10, choices=Source.choices, default=Source.MANUAL)
    # Sealed team key for this person, or null while waiting for a
    # manager's app to seal one (the person is "pending").
    wrapped_key = models.JSONField(null=True, blank=True)
    key_version = models.PositiveIntegerField(default=0)
    # The account public key the copy was sealed to, so a new key pair
    # (after a personal vault reset) makes the old copy pending again.
    sealed_to = models.CharField(max_length=64, blank=True)
    granted_by = models.ForeignKey(Account, null=True, on_delete=models.SET_NULL, related_name="+")
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        constraints = [models.UniqueConstraint(fields=["team", "account"], name="unique_team_access")]

    @property
    def has_current_key(self) -> bool:
        return self.wrapped_key is not None and self.key_version == self.team.key_version

    @property
    def can_write(self) -> bool:
        return self.role in (self.Role.MANAGER, self.Role.EDITOR)


class TeamItem(models.Model):
    team = models.ForeignKey(TeamVault, related_name="items", on_delete=models.CASCADE)
    item_id = models.UUIDField()
    revision = models.PositiveBigIntegerField()
    deleted = models.BooleanField(default=False)
    nonce = models.CharField(max_length=32)
    ciphertext = models.TextField()
    size_bytes = models.PositiveIntegerField()
    updated_by = models.ForeignKey(Account, null=True, on_delete=models.SET_NULL, related_name="+")
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        constraints = [models.UniqueConstraint(fields=["team", "item_id"], name="unique_item_per_team")]
        indexes = [models.Index(fields=["team", "revision"], name="team_item_rev_idx")]

    def as_wire(self):
        return {"id": str(self.item_id), "revision": self.revision, "deleted": self.deleted, "nonce": self.nonce, "ciphertext": self.ciphertext}


class TeamGroupRule(models.Model):
    """Everyone in this Microsoft 365 group gets this role in the team."""

    team = models.ForeignKey(TeamVault, related_name="group_rules", on_delete=models.CASCADE)
    group_id = models.CharField(max_length=64)
    group_name = models.CharField(max_length=256)
    role = models.CharField(max_length=10, choices=TeamAccess.Role.choices, default=TeamAccess.Role.EDITOR)

    class Meta:
        constraints = [models.UniqueConstraint(fields=["team", "group_id"], name="unique_team_group_rule")]
