"""Team vault access changes shared by the API, the console, offboarding
and Microsoft 365 group sync."""

from django.db import transaction

from orgs.models import AuditLogEntry, Membership

from .models import TeamAccess, TeamGroupRule, TeamVault

Role = TeamAccess.Role


def is_org_admin(org, account) -> bool:
    return Membership.objects.filter(
        organization=org, account=account, removed_at__isnull=True, role__in=(Membership.Role.OWNER, Membership.Role.ADMIN)
    ).exists()


def is_org_member(org, account) -> bool:
    return Membership.objects.filter(organization=org, account=account, removed_at__isnull=True).exists()


def remove_access(access: TeamAccess, actor, source: str) -> None:
    """Remove one person's access. If they ever held the key, the team key
    must be replaced: their copy still opens anything sealed with it."""
    team = access.team
    held_key = access.wrapped_key is not None or access.key_version > 0
    email = access.account.email
    access.delete()
    if held_key and not team.needs_rotation:
        team.needs_rotation = True
        team.save(update_fields=["needs_rotation"])
    AuditLogEntry.record(
        organization=team.organization, actor=actor, action="team.member_removed", obj=team,
        team=team.name, member_email=email, source=source, rotation_needed=held_key,
    )


def offboard_account(org, account, actor, source: str) -> int:
    n = 0
    for access in TeamAccess.objects.filter(team__organization=org, account=account).select_related("team", "account"):
        remove_access(access, actor, source)
        n += 1
    return n


def _best(roles):
    return max(roles, key=lambda r: TeamAccess.RANK[r])


@transaction.atomic
def apply_group_rules(org, actor=None) -> dict:
    """Make group-sourced access match the Microsoft 365 group rules.
    Access added by hand is never changed here."""
    added = removed = changed = 0
    members = list(Membership.objects.filter(organization=org, removed_at__isnull=True).select_related("account"))
    for team in TeamVault.objects.filter(organization=org).prefetch_related("group_rules"):
        rules = list(team.group_rules.all())
        desired = {}
        for m in members:
            groups = set(m.entra_groups or [])
            roles = [r.role for r in rules if r.group_id in groups]
            if roles:
                desired[m.account_id] = _best(roles)
        current = {a.account_id: a for a in TeamAccess.objects.filter(team=team).select_related("account", "team")}
        for account_id, access in current.items():
            if access.source != TeamAccess.Source.GROUP:
                continue
            if account_id not in desired:
                remove_access(access, actor, "microsoft365 group rule")
                removed += 1
            elif access.role != desired[account_id]:
                access.role = desired[account_id]
                access.save(update_fields=["role"])
                changed += 1
        for account_id, role in desired.items():
            if account_id not in current:
                TeamAccess.objects.create(team=team, account_id=account_id, role=role, source=TeamAccess.Source.GROUP)
                added += 1
        if added or removed or changed:
            AuditLogEntry.record(
                organization=org, actor=actor, action="team.group_rules_applied", obj=team,
                team=team.name, added=added, removed=removed, changed=changed,
            )
    return {"added": added, "removed": removed, "changed": changed}


def rule_group_ids(org) -> set:
    return set(TeamGroupRule.objects.filter(team__organization=org).values_list("group_id", flat=True))
