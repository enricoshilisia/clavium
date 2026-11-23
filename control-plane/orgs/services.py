"""Organization operations shared by the REST API, the admin console and
SCIM, so offboarding means exactly the same thing everywhere."""

from django.db import transaction
from django.utils import timezone

from .models import AuditLogEntry, Membership


def revoke_all_devices(account):
    now = timezone.now()
    count = 0
    for device in account.devices.filter(revoked_at__isnull=True):
        device.revoked_at = now
        device.save(update_fields=["revoked_at"])
        device.tokens.filter(revoked_at__isnull=True).update(revoked_at=now)
        count += 1
    return count


@transaction.atomic
def offboard(org, membership, actor, *, revoke_devices=False, source="console"):
    """Remove a member: their shared-vault access in this organization
    goes immediately (wrapped keys deleted, shared vault keys marked for
    rotation), and optionally every device they are signed in on."""
    from vaults.models import SharedVault, WrappedVaultKey

    grants = WrappedVaultKey.objects.filter(shared_vault__organization=org, device__account=membership.account)
    vault_ids = list(grants.values_list("shared_vault_id", flat=True).distinct())
    grant_count = grants.count()
    grants.delete()
    # Anything the person could read before is assumed seen; the next
    # admin client to open these vaults rotates their key.
    SharedVault.objects.filter(id__in=vault_ids).update(needs_rotation=True)

    devices = revoke_all_devices(membership.account) if revoke_devices else 0
    membership.removed_at = timezone.now()
    membership.save(update_fields=["removed_at"])
    AuditLogEntry.record(
        organization=org,
        actor=actor,
        action="member.removed",
        obj=membership,
        member_email=membership.account.email,
        shared_vault_grants_revoked=grant_count,
        devices_revoked=devices,
        source=source,
    )
    return {"shared_vault_grants_revoked": grant_count, "devices_revoked": devices, "vaults_needing_rotation": len(vault_ids)}


def is_last_owner(org, membership):
    if membership.role != Membership.Role.OWNER:
        return False
    return not Membership.objects.filter(
        organization=org, role=Membership.Role.OWNER, removed_at__isnull=True
    ).exclude(id=membership.id).exists()
