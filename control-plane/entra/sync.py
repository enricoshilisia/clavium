"""Microsoft 365 directory sync: make an organization's Clavium members
match the chosen Entra ID groups.

Rules
- Anyone enabled in a chosen group (nested groups count) is a member.
  New people get an account and an invite email.
- Anyone disabled in Entra, or no longer in any chosen group, is removed
  with the same offboarding as the console: shared-vault access revoked,
  every device signed out, shared vaults marked for key rotation.
- With an admins group set, its members are admins and everyone else
  synced is a member. Owners are never changed by the sync.
- Safety: if one run would remove more than 20% of synced members (and
  more than 5 people), or the groups suddenly look empty, nothing is
  removed. The run is held until an admin approves it in the console.
  A wrong group change or a Graph hiccup must not lock out a company.
- If Microsoft cannot be reached, nothing changes.
"""

from django.db import transaction
from django.utils import timezone

from accounts.models import Account
from orgs.emails import public_base, send_invite
from orgs.models import AuditLogEntry, Invite, Membership
from orgs.services import is_last_owner, offboard

from . import graph
from .models import DirectoryConnection

SAFETY_MIN = 5
SAFETY_FRACTION = 0.2
LIST_CAP = 50

Status = DirectoryConnection.Status


def _short(items):
    return items[:LIST_CAP]


def _audit(org, actor, action, obj, **meta):
    AuditLogEntry.record(organization=org, actor=actor, action=action, obj=obj, source="microsoft365", **meta)


def run(conn: DirectoryConnection, *, actor=None, approve_removals=False, request=None, client=None) -> dict:
    org = conn.organization
    if not conn.groups:
        conn.status = Status.NEEDS_GROUPS
        conn.save(update_fields=["status"])
        return {"skipped": "no groups chosen"}
    if conn.status == Status.PAUSED and actor is None:
        return {"skipped": "paused"}

    # 1. Read Microsoft first, change nothing until every read succeeded.
    try:
        client = client or graph.client_for(conn.tenant_id)
        directory = {}
        for g in conn.groups:
            for u in client.group_users(g["id"]):
                directory[u["id"]] = u
        admin_ids = {u["id"] for u in client.group_users(conn.admin_group_id)} if conn.admin_group_id else None
    except graph.GraphError as e:
        conn.status = Status.ERROR
        conn.last_error = str(e)
        conn.last_sync_at = timezone.now()
        conn.save(update_fields=["status", "last_error", "last_sync_at"])
        _audit(org, actor, "directory.sync_failed", conn, error=str(e)[:500])
        return {"error": str(e)}

    def eligible(u):
        return u["enabled"] and "@" in u["email"] and (conn.include_guests or not u["guest"])

    wanted = {eid: u for eid, u in directory.items() if eligible(u)}

    def reason(m):
        u = directory.get(m.external_id)
        if u is None:
            return "no longer in the chosen groups"
        if not u["enabled"]:
            return "disabled in Microsoft 365"
        if u["guest"] and not conn.include_guests:
            return "guest account"
        return "no usable email in Microsoft 365"

    base = public_base(request)
    out = {k: [] for k in ("added", "linked", "reactivated", "promoted", "demoted", "removed", "kept_last_owner", "not_in_directory")}
    out["invites_emailed"] = 0
    invites_shown = []

    with transaction.atomic():
        memberships = list(Membership.objects.select_for_update().filter(organization=org).select_related("account"))
        by_ext = {m.external_id: m for m in memberships if m.entra_managed and m.external_id}
        by_email = {m.account.email.lower(): m for m in memberships}
        synced_before = sum(1 for m in memberships if m.entra_managed and m.removed_at is None)

        # 2. Joiners, returners, role changes.
        for eid, u in wanted.items():
            m = by_ext.get(eid) or by_email.get(u["email"])
            target_role = None if admin_ids is None else (Membership.Role.ADMIN if eid in admin_ids else Membership.Role.MEMBER)
            needs_invite = False
            if m is None:
                account = Account.objects.filter(email__iexact=u["email"]).first()
                if account is None:
                    account = Account.objects.create(email=u["email"], display_name=u["name"][:200])
                    account.set_unusable_password()
                    account.save()
                m = Membership.objects.create(
                    organization=org, account=account, role=target_role or Membership.Role.MEMBER,
                    external_id=eid, entra_managed=True,
                )
                out["added"].append(u["email"])
                _audit(org, actor, "member.provisioned", m, member_email=u["email"])
                needs_invite = True
            else:
                fields = []
                if not m.entra_managed or m.external_id != eid:
                    if not m.entra_managed and m.removed_at is None:
                        out["linked"].append(u["email"])
                    m.entra_managed, m.external_id = True, eid
                    fields += ["entra_managed", "external_id"]
                if m.removed_at is not None:
                    m.removed_at = None
                    fields.append("removed_at")
                    if not m.account.is_active:
                        m.account.is_active = True
                        m.account.save(update_fields=["is_active"])
                    out["reactivated"].append(u["email"])
                    _audit(org, actor, "member.reactivated", m, member_email=u["email"])
                    needs_invite = True
                if fields:
                    m.save(update_fields=fields)
            if target_role and m.role != Membership.Role.OWNER and m.role != target_role:
                old, m.role = m.role, target_role
                m.save(update_fields=["role"])
                (out["promoted"] if target_role == Membership.Role.ADMIN else out["demoted"]).append(u["email"])
                _audit(org, actor, "member.role_changed", m, member_email=u["email"], old=old, new=target_role)
            if needs_invite and not m.account.has_usable_password():
                _, raw = Invite.issue(org, m.account)
                if conn.send_invites and send_invite(org, m.account, raw, base):
                    out["invites_emailed"] += 1
                else:
                    invites_shown.append(u["email"])

        # 3. Leavers.
        leaving = [m for m in memberships if m.entra_managed and m.removed_at is None and m.external_id not in wanted]
        held = False
        if leaving and conn.auto_remove and not approve_removals:
            too_many = len(leaving) > max(SAFETY_MIN, SAFETY_FRACTION * synced_before)
            if too_many or not wanted:
                held = True
        if leaving and (not conn.auto_remove or held):
            out["not_in_directory"] = [{"membership_id": str(m.id), "email": m.account.email, "reason": reason(m)} for m in leaving]
        elif leaving:
            for m in leaving:
                if is_last_owner(org, m):
                    out["kept_last_owner"].append(m.account.email)
                    continue
                offboard(org, m, actor, revoke_devices=True, source=f"microsoft365: {reason(m)}")
                if not m.account.memberships.filter(removed_at__isnull=True).exists():
                    m.account.is_active = False
                    m.account.save(update_fields=["is_active"])
                out["removed"].append(m.account.email)

        changes = sum(len(out[k]) for k in ("added", "linked", "reactivated", "promoted", "demoted", "removed"))
        summary = {k: _short(v) if isinstance(v, list) else v for k, v in out.items()}
        summary["in_directory"] = len(wanted)
        summary["invites_to_send_by_hand"] = _short(invites_shown)
        conn.last_result = summary
        conn.last_sync_at = timezone.now()
        conn.last_error = ""
        conn.held_removals = summary["not_in_directory"] if held else []
        conn.status = Status.HELD if held else (Status.PAUSED if conn.status == Status.PAUSED else Status.ACTIVE)
        conn.save(update_fields=["last_result", "last_sync_at", "last_error", "held_removals", "status"])
        if changes or held:
            _audit(org, actor, "directory.synced", conn, held_removals=len(leaving) if held else 0,
                   **{k: len(out[k]) for k in ("added", "linked", "reactivated", "promoted", "demoted", "removed")})
    summary["held"] = held
    return summary


def run_all(stdout=None) -> int:
    n = 0
    for conn in DirectoryConnection.objects.select_related("organization").exclude(status=Status.PAUSED):
        if not conn.groups:
            continue
        result = run(conn)
        n += 1
        if stdout:
            state = result.get("error") or ("removals held for approval" if result.get("held") else "ok")
            stdout.write(f"{conn.organization.name}: {state}")
    return n
