"""The organization admin console: members, devices, policy, health,
SCIM provisioning and the audit log. Server-rendered, session sign-in with
the Clavium account (owners and admins only). It never sees vault
contents: everything here is metadata the control plane already holds."""

from accounts import email_verification

from django.contrib import messages
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.core.cache import cache
from django.db.models import Avg, Count, Q
from django.shortcuts import get_object_or_404, redirect, render
from django.utils import timezone
from django.views.decorators.http import require_POST

from accounts.models import Account, Device
from orgs.models import AuditLogEntry, HealthSnapshot, Invite, Membership, Organization, OrgPolicy, ScimToken
from orgs.services import is_last_owner, offboard, revoke_all_devices
from vaults.models import SharedVault

ADMIN_ROLES = (Membership.Role.OWNER, Membership.Role.ADMIN)
LOGIN_URL = "/console/login/"


def _client_ip(request):
    fwd = request.META.get("HTTP_X_FORWARDED_FOR", "")
    return fwd.split(",")[0].strip() if fwd else request.META.get("REMOTE_ADDR", "")


def login_view(request):
    if request.method == "POST":
        key = f"console-login:{_client_ip(request)}"
        attempts = cache.get(key, 0)
        if attempts >= 10:
            messages.error(request, "Too many attempts. Wait a few minutes and try again.")
            return render(request, "console/login.html", status=429)
        user = authenticate(request, username=request.POST.get("email", "").strip().lower(), password=request.POST.get("password", ""))
        if user is None:
            cache.set(key, attempts + 1, 300)
            messages.error(request, "That email and password do not match a Clavium account.")
            return render(request, "console/login.html", status=401)
        if email_verification.blocks_sign_in(user):
            email_verification.send(user, request)
            messages.error(request, f"Verify your email address first. We sent a link to {user.email}.")
            return render(request, "console/login.html", status=403)
        login(request, user)
        AuditLogEntry.record(organization=None, actor=user, action="console.signed_in", obj=user, ip=_client_ip(request))
        return redirect(request.GET.get("next") or "console-home")
    return render(request, "console/login.html")


def logout_view(request):
    logout(request)
    return redirect("console-login")


def _admin_orgs(user):
    return Organization.objects.filter(memberships__account=user, memberships__removed_at__isnull=True, memberships__role__in=ADMIN_ROLES).distinct()


@login_required(login_url=LOGIN_URL)
def home(request):
    orgs = list(_admin_orgs(request.user))
    if len(orgs) == 1:
        return redirect("console-org", org_id=orgs[0].id)
    return render(request, "console/home.html", {"orgs": orgs})


@login_required(login_url=LOGIN_URL)
@require_POST
def create_org(request):
    name = request.POST.get("name", "").strip()[:200]
    if not name:
        messages.error(request, "Give the organization a name.")
        return redirect("console-home")
    org = Organization.objects.create(name=name, created_by=request.user)
    Membership.objects.create(organization=org, account=request.user, role=Membership.Role.OWNER, added_by=request.user)
    OrgPolicy.objects.create(organization=org)
    AuditLogEntry.record(organization=org, actor=request.user, action="organization.created", obj=org, source="console")
    return redirect("console-org", org_id=org.id)


def _org_for_admin(request, org_id):
    org = get_object_or_404(Organization, id=org_id)
    me = Membership.objects.filter(organization=org, account=request.user, removed_at__isnull=True, role__in=ADMIN_ROLES).first()
    return org, me


@login_required(login_url=LOGIN_URL)
def org_dashboard(request, org_id):
    org, me = _org_for_admin(request, org_id)
    if me is None:
        return render(request, "console/forbidden.html", status=403)
    policy, _ = OrgPolicy.objects.get_or_create(organization=org)
    members = list(
        Membership.objects.filter(organization=org, removed_at__isnull=True)
        .select_related("account")
        .annotate(active_devices=Count("account__devices", filter=Q(account__devices__revoked_at__isnull=True)))
        .order_by("account__email")
    )
    health = {h.account_id: h for h in HealthSnapshot.objects.filter(account__in=[m.account for m in members])}
    for m in members:
        m.health = health.get(m.account_id)
        m.pending_invite = not m.account.has_usable_password()
    account_ids = [m.account_id for m in members]
    devices = Device.objects.filter(account_id__in=account_ids, revoked_at__isnull=True).select_related("account").order_by("-last_seen_at")
    avg = HealthSnapshot.objects.filter(account_id__in=account_ids).aggregate(a=Avg("score"))["a"]
    removed = Membership.objects.filter(organization=org, removed_at__isnull=False).select_related("account").order_by("-removed_at")[:20]
    ctx = {
        "org": org,
        "me": me,
        "policy": policy,
        "members": members,
        "removed": removed,
        "devices": devices,
        "avg_health": round(avg) if avg is not None else None,
        "reported": len(health),
        "rotation_needed": SharedVault.objects.filter(organization=org, needs_rotation=True).count(),
        "scim_tokens": ScimToken.objects.filter(organization=org, revoked_at__isnull=True).order_by("-created_at"),
        "audit": org.audit_entries.select_related("actor")[:100],
        "roles": Membership.Role.choices,
        "scim_base": request.build_absolute_uri("/scim/v2/"),
        "new_secret": request.session.pop("console_secret", None),
        "ms": entra_console_context(request, org),
    }
    return render(request, "console/org.html", ctx)


def entra_console_context(request, org):
    from entra.views import console_context  # entra imports this module

    return console_context(request, org)


@login_required(login_url=LOGIN_URL)
@require_POST
def org_action(request, org_id):
    org, me = _org_for_admin(request, org_id)
    if me is None:
        return render(request, "console/forbidden.html", status=403)
    action = request.POST.get("action")
    back = redirect("console-org", org_id=org.id)

    def member():
        return get_object_or_404(Membership, id=request.POST.get("membership_id"), organization=org)

    if action == "add_member":
        email = request.POST.get("email", "").strip().lower()
        role = request.POST.get("role", Membership.Role.MEMBER)
        if role not in dict(Membership.Role.choices) or (role == Membership.Role.OWNER and me.role != Membership.Role.OWNER):
            messages.error(request, "You cannot give that role.")
            return back
        if "@" not in email:
            messages.error(request, "Enter an email address.")
            return back
        account = Account.objects.filter(email__iexact=email).first()
        if account is None:
            account = Account.objects.create(email=email)
            account.set_unusable_password()
            account.save()
        m = Membership.objects.filter(organization=org, account=account).first()
        if m and m.removed_at is None:
            messages.info(request, f"{email} is already a member.")
            return back
        if m:
            m.removed_at, m.role, m.added_by = None, role, request.user
            m.save()
        else:
            m = Membership.objects.create(organization=org, account=account, role=role, added_by=request.user)
        AuditLogEntry.record(organization=org, actor=request.user, action="member.added", obj=m, member_email=email, role=role, source="console")
        if not account.has_usable_password():
            _, raw = Invite.issue(org, account)
            request.session["console_secret"] = {
                "title": f"Invite link for {email}",
                "value": request.build_absolute_uri(f"/console/invite/{raw}/"),
                "help": "Send this to them. It lets them set their account password and is valid for 7 days, once.",
            }
        else:
            messages.success(request, f"Added {email}.")
        return back

    if action == "invite_link":
        m = member()
        _, raw = Invite.issue(org, m.account)
        request.session["console_secret"] = {
            "title": f"Invite link for {m.account.email}",
            "value": request.build_absolute_uri(f"/console/invite/{raw}/"),
            "help": "Valid for 7 days, once.",
        }
        return back

    if action == "change_role":
        m = member()
        role = request.POST.get("role")
        if role not in dict(Membership.Role.choices):
            return back
        if (role == Membership.Role.OWNER or m.role == Membership.Role.OWNER) and me.role != Membership.Role.OWNER:
            messages.error(request, "Only an owner can change owner roles.")
            return back
        if m.role == Membership.Role.OWNER and role != Membership.Role.OWNER and is_last_owner(org, m):
            messages.error(request, "The organization needs at least one owner.")
            return back
        old = m.role
        m.role = role
        m.save(update_fields=["role"])
        AuditLogEntry.record(organization=org, actor=request.user, action="member.role_changed", obj=m, member_email=m.account.email, old=old, new=role)
        messages.success(request, f"{m.account.email} is now {m.get_role_display().lower()}.")
        return back

    if action == "remove_member":
        m = member()
        if is_last_owner(org, m):
            messages.error(request, "You cannot remove the last owner.")
            return back
        result = offboard(org, m, request.user, revoke_devices=request.POST.get("revoke_devices") == "on")
        messages.success(
            request,
            f"Removed {m.account.email}: {result['devices_revoked']} device(s) signed out, "
            f"{result['shared_vault_grants_revoked']} shared-vault grant(s) revoked.",
        )
        return back

    if action == "revoke_device":
        d = get_object_or_404(Device, id=request.POST.get("device_id"), account__memberships__organization=org, account__memberships__removed_at__isnull=True)
        now = timezone.now()
        d.revoked_at = now
        d.save(update_fields=["revoked_at"])
        d.tokens.filter(revoked_at__isnull=True).update(revoked_at=now)
        AuditLogEntry.record(organization=org, actor=request.user, action="device.revoked", obj=d, member_email=d.account.email, device=d.name)
        messages.success(request, f"Signed out {d.name} ({d.account.email}).")
        return back

    if action == "signout_all":
        m = member()
        n = revoke_all_devices(m.account)
        AuditLogEntry.record(organization=org, actor=request.user, action="member.signed_out_everywhere", obj=m, member_email=m.account.email, devices=n)
        messages.success(request, f"Signed {m.account.email} out of {n} device(s).")
        return back

    if action == "policy":
        p, _ = OrgPolicy.objects.get_or_create(organization=org)
        try:
            p.min_master_password_length = max(8, min(128, int(request.POST.get("min_master_password_length", 12))))
            p.max_auto_lock_minutes = max(0, min(1440, int(request.POST.get("max_auto_lock_minutes", 15))))
        except ValueError:
            messages.error(request, "Enter whole numbers.")
            return back
        p.allow_export = request.POST.get("allow_export") == "on"
        p.require_recovery_key = request.POST.get("require_recovery_key") == "on"
        p.updated_by = request.user
        p.save()
        AuditLogEntry.record(organization=org, actor=request.user, action="policy.updated", obj=p, **p.as_dict())
        messages.success(request, "Policy saved. Apps pick it up on their next sync.")
        return back

    if action == "scim_create":
        token, raw = ScimToken.issue(org, request.user, request.POST.get("label", "").strip()[:100] or "Identity provider")
        AuditLogEntry.record(organization=org, actor=request.user, action="scim.token_created", obj=token, label=token.label)
        request.session["console_secret"] = {
            "title": "SCIM token",
            "value": raw,
            "help": "Paste this as the Secret Token in your identity provider's provisioning settings. It is shown only once.",
        }
        return back

    if action == "scim_revoke":
        token = get_object_or_404(ScimToken, id=request.POST.get("token_id"), organization=org)
        token.revoked_at = timezone.now()
        token.save(update_fields=["revoked_at"])
        AuditLogEntry.record(organization=org, actor=request.user, action="scim.token_revoked", obj=token, label=token.label)
        messages.success(request, "SCIM token revoked.")
        return back

    messages.error(request, "Unknown action.")
    return back


def invite(request, token):
    inv = Invite.find(token)
    if inv is None:
        return render(request, "console/invite.html", {"invalid": True}, status=404)
    if request.method == "POST":
        pw1, pw2 = request.POST.get("password", ""), request.POST.get("password2", "")
        min_len = 10  # account password; the master password policy is enforced in the apps
        if len(pw1) < min_len:
            messages.error(request, f"Use at least {min_len} characters.")
        elif pw1 != pw2:
            messages.error(request, "The two passwords do not match.")
        else:
            inv.account.set_password(pw1)
            inv.account.is_active = True
            inv.account.save()
            inv.used_at = timezone.now()
            inv.save(update_fields=["used_at"])
            AuditLogEntry.record(organization=inv.organization, actor=inv.account, action="invite.accepted", obj=inv)
            return render(request, "console/invite.html", {"done": True, "inv": inv})
    return render(request, "console/invite.html", {"inv": inv})
