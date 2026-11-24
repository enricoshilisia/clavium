from django.db import models

from accounts.models import Account
from orgs.models import Organization


class DirectoryConnection(models.Model):
    """One organization's link to its Microsoft 365 (Entra ID) tenant."""

    class Status(models.TextChoices):
        NEEDS_GROUPS = "needs_groups", "Choose groups"
        ACTIVE = "active", "Syncing"
        HELD = "held", "Waiting for approval"
        ERROR = "error", "Problem"
        PAUSED = "paused", "Paused"

    organization = models.OneToOneField(Organization, related_name="directory", on_delete=models.CASCADE)
    # One tenant feeds one organization.
    tenant_id = models.CharField(max_length=64, unique=True)
    status = models.CharField(max_length=20, choices=Status.choices, default=Status.NEEDS_GROUPS)
    # [{"id": ..., "name": ...}] — people in any of these get Clavium.
    groups = models.JSONField(default=list, blank=True)
    # Optional: members of this group are admins in Clavium.
    admin_group_id = models.CharField(max_length=64, blank=True)
    admin_group_name = models.CharField(max_length=256, blank=True)
    auto_remove = models.BooleanField(default=True, help_text="Remove people from Clavium when they leave the groups or are disabled.")
    send_invites = models.BooleanField(default=True, help_text="Email an invite to people added by the sync.")
    include_guests = models.BooleanField(default=False)

    connected_by = models.ForeignKey(Account, null=True, on_delete=models.SET_NULL, related_name="+")
    connected_at = models.DateTimeField(auto_now_add=True)
    last_sync_at = models.DateTimeField(null=True, blank=True)
    last_result = models.JSONField(default=dict, blank=True)
    last_error = models.TextField(blank=True)
    # Removals the safety check stopped, waiting for an admin to approve.
    held_removals = models.JSONField(default=list, blank=True)

    # Graph change notifications on /users, so a disabled or deleted
    # account is cut off within about a minute instead of at the next
    # scheduled sync. Microsoft echoes client_state back with every
    # notification; only its hash is stored.
    subscription_id = models.CharField(max_length=64, blank=True)
    subscription_expires_at = models.DateTimeField(null=True, blank=True)
    client_state_hash = models.CharField(max_length=64, blank=True)
    subscription_error = models.TextField(blank=True)
    # Set by a notification; the next timer tick (every minute) syncs.
    sync_requested_at = models.DateTimeField(null=True, blank=True)

    def group_ids(self):
        return [g["id"] for g in self.groups]

    def __str__(self):
        return f"{self.organization} -> {self.tenant_id}"
