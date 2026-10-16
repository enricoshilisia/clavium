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
