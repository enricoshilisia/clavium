import uuid

from django.db import models

from accounts.models import Account


class Organization(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=200)
    created_by = models.ForeignKey(Account, related_name="organizations_created", on_delete=models.PROTECT)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.name


class Membership(models.Model):
    class Role(models.TextChoices):
        OWNER = "owner", "Owner"
        ADMIN = "admin", "Admin"
        MEMBER = "member", "Member"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    organization = models.ForeignKey(Organization, related_name="memberships", on_delete=models.CASCADE)
    account = models.ForeignKey(Account, related_name="memberships", on_delete=models.CASCADE)
    role = models.CharField(max_length=10, choices=Role.choices, default=Role.MEMBER)
    added_by = models.ForeignKey(
        Account, related_name="memberships_added", null=True, on_delete=models.SET_NULL
    )
    joined_at = models.DateTimeField(auto_now_add=True)
    removed_at = models.DateTimeField(null=True, blank=True)
    # Set when an identity provider manages this member over SCIM.
    external_id = models.CharField(max_length=255, blank=True)
    scim_managed = models.BooleanField(default=False)
    # Added and removed by Microsoft 365 directory sync (external_id is
    # then the Entra object id).
    entra_managed = models.BooleanField(default=False)
    # Microsoft 365 group ids this person is in (of the groups Clavium
    # reads), recorded by directory sync for team vault group rules.
    entra_groups = models.JSONField(default=list, blank=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=["organization", "account"], name="unique_membership")
        ]

    def __str__(self):
        return f"{self.account.email} @ {self.organization.name} ({self.role})"

    @property
    def is_active(self) -> bool:
        return self.removed_at is None


class AuditLogEntry(models.Model):
    """Append-only. `save()` refuses to update an existing row and
    `delete()` always raises — the same two guarantees Tenrix's own audit
    log enforces, and for the same reason: an audit trail that can be
    quietly edited after the fact is not an audit trail.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    organization = models.ForeignKey(
        Organization, related_name="audit_entries", null=True, on_delete=models.SET_NULL
    )
    actor = models.ForeignKey(
        Account, related_name="audit_entries", null=True, on_delete=models.SET_NULL
    )
    action = models.CharField(max_length=100)
    object_type = models.CharField(max_length=100)
    object_id = models.CharField(max_length=64)
    metadata = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]
        verbose_name_plural = "audit log entries"

    def __str__(self):
        return f"{self.action} {self.object_type}:{self.object_id}"

    def save(self, *args, **kwargs):
        if self.pk and AuditLogEntry.objects.filter(pk=self.pk).exists():
            raise ValueError("audit log entries are append-only and cannot be updated")
        super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        raise ValueError("audit log entries are append-only and cannot be deleted")

    @classmethod
    def record(cls, *, organization, actor, action, obj, **metadata):
        return cls.objects.create(
            organization=organization,
            actor=actor,
            action=action,
            object_type=obj.__class__.__name__,
            object_id=str(obj.pk),
            metadata=metadata,
        )


class OrgPolicy(models.Model):
    """Rules an organization sets for its members' apps. Enforced by the
    clients (the server cannot see inside a vault); when someone belongs
    to several organizations, the strictest value of each rule applies."""

    organization = models.OneToOneField(Organization, related_name="policy", on_delete=models.CASCADE)
    min_master_password_length = models.PositiveSmallIntegerField(default=12)
    max_auto_lock_minutes = models.PositiveSmallIntegerField(default=15)
    allow_export = models.BooleanField(default=True)
    require_recovery_key = models.BooleanField(default=False)
    updated_at = models.DateTimeField(auto_now=True)
    updated_by = models.ForeignKey(Account, null=True, blank=True, on_delete=models.SET_NULL, related_name="+")

    DEFAULTS = {
        "min_master_password_length": 10,
        "max_auto_lock_minutes": 0,  # 0 = no limit
        "allow_export": True,
        "require_recovery_key": False,
    }

    def as_dict(self):
        return {
            "min_master_password_length": self.min_master_password_length,
            "max_auto_lock_minutes": self.max_auto_lock_minutes,
            "allow_export": self.allow_export,
            "require_recovery_key": self.require_recovery_key,
        }

    @classmethod
    def effective_for(cls, account):
        """The strictest combination across every org this account is in."""
        eff = dict(cls.DEFAULTS)
        sources = []
        for p in cls.objects.filter(
            organization__memberships__account=account, organization__memberships__removed_at__isnull=True
        ).select_related("organization"):
            sources.append(p.organization.name)
            eff["min_master_password_length"] = max(eff["min_master_password_length"], p.min_master_password_length)
            if p.max_auto_lock_minutes:
                cur = eff["max_auto_lock_minutes"]
                eff["max_auto_lock_minutes"] = p.max_auto_lock_minutes if not cur else min(cur, p.max_auto_lock_minutes)
            eff["allow_export"] = eff["allow_export"] and p.allow_export
            eff["require_recovery_key"] = eff["require_recovery_key"] or p.require_recovery_key
        eff["organizations"] = sources
        return eff


class HealthSnapshot(models.Model):
    """Aggregate password-health numbers an app reports for its own vault.
    Counts only: never which items, sites or passwords."""

    account = models.OneToOneField(Account, related_name="health_snapshot", on_delete=models.CASCADE)
    score = models.PositiveSmallIntegerField()
    total = models.PositiveIntegerField()
    weak = models.PositiveIntegerField()
    reused = models.PositiveIntegerField()
    old = models.PositiveIntegerField()
    without_totp = models.PositiveIntegerField()
    has_recovery_key = models.BooleanField(default=False)
    reported_at = models.DateTimeField(auto_now=True)


def _hash(raw: str) -> str:
    import hashlib

    return hashlib.sha256(raw.encode()).hexdigest()


class ScimToken(models.Model):
    """Bearer token an identity provider (Entra ID, Okta, Google) uses to
    provision and deprovision this organization's members via SCIM 2.0.
    Only the hash is stored; the raw value is shown once."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    organization = models.ForeignKey(Organization, related_name="scim_tokens", on_delete=models.CASCADE)
    label = models.CharField(max_length=100, default="Identity provider")
    token_hash = models.CharField(max_length=64, unique=True)
    created_by = models.ForeignKey(Account, null=True, on_delete=models.SET_NULL, related_name="+")
    created_at = models.DateTimeField(auto_now_add=True)
    last_used_at = models.DateTimeField(null=True, blank=True)
    revoked_at = models.DateTimeField(null=True, blank=True)

    @classmethod
    def issue(cls, organization, created_by, label="Identity provider"):
        import secrets

        raw = "scim_" + secrets.token_urlsafe(32)
        return cls.objects.create(organization=organization, created_by=created_by, label=label, token_hash=_hash(raw)), raw

    @classmethod
    def authenticate(cls, raw: str):
        return cls.objects.select_related("organization").filter(token_hash=_hash(raw), revoked_at__isnull=True).first()


class Invite(models.Model):
    """A link that lets a provisioned (or invited) person set their account
    password. Single use, expires after 7 days."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    organization = models.ForeignKey(Organization, related_name="invites", on_delete=models.CASCADE)
    account = models.ForeignKey(Account, related_name="invites", on_delete=models.CASCADE)
    token_hash = models.CharField(max_length=64, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)
    used_at = models.DateTimeField(null=True, blank=True)

    @classmethod
    def issue(cls, organization, account):
        import secrets

        raw = secrets.token_urlsafe(24)
        return cls.objects.create(organization=organization, account=account, token_hash=_hash(raw)), raw

    @classmethod
    def find(cls, raw: str):
        from datetime import timedelta

        from django.utils import timezone

        inv = cls.objects.select_related("account", "organization").filter(token_hash=_hash(raw), used_at__isnull=True).first()
        if inv and inv.created_at > timezone.now() - timedelta(days=7):
            return inv
        return None
