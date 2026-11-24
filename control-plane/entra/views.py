"""Console screens for Microsoft 365 directory sync.

Connecting takes two Microsoft round trips, on purpose:

1. Admin consent. A Global Administrator approves Clavium's read-only
   permissions for their tenant. Microsoft redirects back with the tenant
   id, but that redirect is not signed: anyone could type a URL claiming
   any tenant.
2. Sign-in. So the admin then signs in with OpenID Connect, and Clavium
   redeems the code with Microsoft directly. The `tid` in that ID token
   must equal the consented tenant. Only then is the connection saved.

Both legs are bound to the browser session with a one-time random
state, expire after 15 minutes, and need a console owner or admin.
"""

import base64
import json
import secrets
import time
import urllib.parse

from django.conf import settings
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.db import IntegrityError, transaction
from django.shortcuts import get_object_or_404, redirect
from django.views.decorators.http import require_POST

from console.views import LOGIN_URL, _org_for_admin
from orgs.emails import public_base
from orgs.models import AuditLogEntry, Membership

from . import graph, sync
from .graph import GraphError, _request
from .models import DirectoryConnection

FLOW_KEY = "entra_flow"
FLOW_TTL = 15 * 60


def _redirect_uri(request, leg):
    return f"{public_base(request)}/console/microsoft/{leg}/"


def _audit(org, actor, action, obj, **meta):
    AuditLogEntry.record(organization=org, actor=actor, action=action, obj=obj, source="console", **meta)


def console_context(request, org):
    """Extra context for the org dashboard's Microsoft 365 card."""
    ctx = {"configured": graph.configured(), "conn": None, "results": None, "q": None, "error": None}
    conn = DirectoryConnection.objects.filter(organization=org).first()
    ctx["conn"] = conn
    if conn:
        ctx["synced_members"] = Membership.objects.filter(organization=org, entra_managed=True, removed_at__isnull=True).count()
    q = request.GET.get("ms_q")
    if conn and q is not None:
        ctx["q"] = q
        try:
            chosen = set(conn.group_ids())
            ctx["results"] = [g for g in graph.client_for(conn.tenant_id).search_groups(q) if g["id"] not in chosen]
        except GraphError as e:
            ctx["error"] = str(e)
    return ctx


@login_required(login_url=LOGIN_URL)
@require_POST
def connect(request, org_id):
    org, me = _org_for_admin(request, org_id)
    if me is None or not graph.configured():
        return redirect("console-org", org_id=org_id)
    state = secrets.token_urlsafe(24)
    request.session[FLOW_KEY] = {"org": str(org.id), "state": state, "nonce": secrets.token_urlsafe(24), "at": time.time()}
    return redirect(graph.admin_consent_url(_redirect_uri(request, "consented"), state))


def _flow(request, state):
    flow = request.session.get(FLOW_KEY)
    if not flow or not state or not secrets.compare_digest(flow.get("state", ""), state) or time.time() - flow["at"] > FLOW_TTL:
        return None
    return flow


def _fail(request, org_id, text):
    request.session.pop(FLOW_KEY, None)
    messages.error(request, text)
    return redirect("console-org", org_id=org_id) if org_id else redirect("console-home")


@login_required(login_url=LOGIN_URL)
def consented(request):
    """Leg 1 return: consent granted (or not). Now prove the tenant."""
    flow = _flow(request, request.GET.get("state", ""))
    if flow is None:
        return _fail(request, None, "That Microsoft sign-in link expired. Start again from your organization page.")
    org, me = _org_for_admin(request, flow["org"])
    if me is None:
        return _fail(request, None, "You are no longer an admin of that organization.")
    if request.GET.get("error"):
        desc = (request.GET.get("error_description") or "").split("\r\n")[0][:300]
        if request.GET.get("error") == "access_denied":
            desc = "The approval was cancelled. A Global Administrator needs to approve Clavium's access."
        return _fail(request, org.id, f"Microsoft did not approve the connection. {desc}")
    tenant = request.GET.get("tenant", "")
    if request.GET.get("admin_consent", "").lower() != "true" or not tenant:
        return _fail(request, org.id, "Microsoft did not confirm the approval. Try again.")
    flow.update(tenant=tenant, state=secrets.token_urlsafe(24), at=time.time())
    request.session[FLOW_KEY] = flow
    q = urllib.parse.urlencode(
        {
            "client_id": settings.CLAVIUM_MS_CLIENT_ID,
            "response_type": "code",
            "redirect_uri": _redirect_uri(request, "signed-in"),
            "response_mode": "query",
            "scope": "openid profile email",
            "state": flow["state"],
            "nonce": flow["nonce"],
        }
    )
    return redirect(f"{settings.CLAVIUM_MS_AUTHORITY}/{urllib.parse.quote(tenant)}/oauth2/v2.0/authorize?{q}")


def _id_token_claims(id_token: str) -> dict:
    # Received straight from Microsoft's token endpoint over TLS in exchange
    # for our client secret, so the signature check is not needed here
    # (OpenID Connect Core 3.1.3.7, point 6).
    payload = id_token.split(".")[1]
    return json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))


@login_required(login_url=LOGIN_URL)
def signed_in(request):
    """Leg 2 return: verify the tenant through a real sign-in, then save."""
    flow = _flow(request, request.GET.get("state", ""))
    if flow is None or "tenant" not in flow:
        return _fail(request, None, "That Microsoft sign-in link expired. Start again from your organization page.")
    org, me = _org_for_admin(request, flow["org"])
    if me is None:
        return _fail(request, None, "You are no longer an admin of that organization.")
    if request.GET.get("error") or not request.GET.get("code"):
        return _fail(request, org.id, "The Microsoft sign-in did not finish. Try connecting again.")
    tenant = flow["tenant"]
    try:
        status, _, body = _request(
            "POST",
            f"{settings.CLAVIUM_MS_AUTHORITY}/{urllib.parse.quote(tenant)}/oauth2/v2.0/token",
            data={
                "client_id": settings.CLAVIUM_MS_CLIENT_ID,
                "client_secret": settings.CLAVIUM_MS_CLIENT_SECRET,
                "grant_type": "authorization_code",
                "code": request.GET["code"],
                "redirect_uri": _redirect_uri(request, "signed-in"),
                "scope": "openid profile email",
            },
        )
    except GraphError as e:
        return _fail(request, org.id, str(e))
    if status != 200 or "id_token" not in body:
        return _fail(request, org.id, "Microsoft did not confirm the sign-in. Try connecting again.")
    claims = _id_token_claims(body["id_token"])
    if (
        claims.get("tid") != tenant
        or claims.get("aud") != settings.CLAVIUM_MS_CLIENT_ID
        or claims.get("nonce") != flow["nonce"]
    ):
        _audit(org, request.user, "directory.connect_rejected", org, reason="tenant mismatch", tenant=tenant[:64])
        return _fail(request, org.id, "The Microsoft account you signed in with does not belong to the tenant that was approved.")
    request.session.pop(FLOW_KEY, None)

    try:
        graph.client_for(tenant).check()
    except GraphError as e:
        return _fail(request, org.id, f"Connected, but Clavium cannot read the directory yet: {e} New approvals can take a minute; try again shortly.")

    conn = DirectoryConnection.objects.filter(organization=org).first()
    if conn and conn.tenant_id != tenant:
        return _fail(request, org.id, "This organization is already connected to a different Microsoft 365 tenant. Disconnect it first.")
    if DirectoryConnection.objects.filter(tenant_id=tenant).exclude(organization=org).exists():
        return _fail(request, org.id, "That Microsoft 365 tenant is already connected to another Clavium organization.")
    try:
        if conn is None:
            with transaction.atomic():
                conn = DirectoryConnection.objects.create(organization=org, tenant_id=tenant, connected_by=request.user)
        else:
            conn.status = DirectoryConnection.Status.ACTIVE if conn.groups else DirectoryConnection.Status.NEEDS_GROUPS
            conn.last_error = ""
            conn.save(update_fields=["status", "last_error"])
    except IntegrityError:
        return _fail(request, org.id, "That Microsoft 365 tenant is already connected to another Clavium organization.")
    _audit(org, request.user, "directory.connected", conn, tenant=tenant, microsoft_user=claims.get("preferred_username", "")[:200])
    messages.success(request, "Microsoft 365 connected. Now choose which groups get Clavium.")
    return redirect(f"/console/{org.id}/?ms_q=#microsoft")


@login_required(login_url=LOGIN_URL)
@require_POST
def action(request, org_id):
    org, me = _org_for_admin(request, org_id)
    if me is None:
        return redirect("console-org", org_id=org_id)
    conn = get_object_or_404(DirectoryConnection, organization=org)
    act = request.POST.get("action")
    back = redirect(f"/console/{org.id}/#microsoft")
    client = None

    def lookup(group_id):
        nonlocal client
        client = client or graph.client_for(conn.tenant_id)
        return client.group(group_id)

    try:
        if act == "add_group":
            g = lookup(request.POST.get("group_id", ""))
            if g["id"] not in conn.group_ids():
                conn.groups = conn.groups + [g]
                if conn.status == DirectoryConnection.Status.NEEDS_GROUPS:
                    conn.status = DirectoryConnection.Status.ACTIVE
                conn.save(update_fields=["groups", "status"])
                _audit(org, request.user, "directory.group_added", conn, group=g["name"])
                messages.success(request, f"Added {g['name']}. Run a sync to bring its people in.")
        elif act == "remove_group":
            gid = request.POST.get("group_id", "")
            name = next((g["name"] for g in conn.groups if g["id"] == gid), gid)
            conn.groups = [g for g in conn.groups if g["id"] != gid]
            if not conn.groups:
                conn.status = DirectoryConnection.Status.NEEDS_GROUPS
            conn.save(update_fields=["groups", "status"])
            _audit(org, request.user, "directory.group_removed", conn, group=name)
            messages.success(request, f"Removed {name}. Its people leave Clavium on the next sync unless they are in another chosen group.")
        elif act == "set_admin_group":
            g = lookup(request.POST.get("group_id", ""))
            conn.admin_group_id, conn.admin_group_name = g["id"], g["name"]
            conn.save(update_fields=["admin_group_id", "admin_group_name"])
            _audit(org, request.user, "directory.admin_group_set", conn, group=g["name"])
            messages.success(request, f"Members of {g['name']} will be Clavium admins.")
        elif act == "clear_admin_group":
            conn.admin_group_id = conn.admin_group_name = ""
            conn.save(update_fields=["admin_group_id", "admin_group_name"])
            _audit(org, request.user, "directory.admin_group_cleared", conn)
            messages.success(request, "Admin roles are now managed by hand in this console.")
        elif act == "settings":
            conn.auto_remove = request.POST.get("auto_remove") == "on"
            conn.send_invites = request.POST.get("send_invites") == "on"
            conn.include_guests = request.POST.get("include_guests") == "on"
            conn.save(update_fields=["auto_remove", "send_invites", "include_guests"])
            _audit(org, request.user, "directory.settings_updated", conn, auto_remove=conn.auto_remove, send_invites=conn.send_invites, include_guests=conn.include_guests)
            messages.success(request, "Saved.")
        elif act in ("sync", "approve_removals"):
            result = sync.run(conn, actor=request.user, approve_removals=act == "approve_removals", request=request)
            _report(request, result)
        elif act == "pause":
            conn.status = DirectoryConnection.Status.PAUSED
            conn.save(update_fields=["status"])
            _audit(org, request.user, "directory.paused", conn)
            messages.success(request, "Automatic sync paused. Nobody is added or removed until you resume.")
        elif act == "resume":
            conn.status = DirectoryConnection.Status.ACTIVE if conn.groups else DirectoryConnection.Status.NEEDS_GROUPS
            conn.save(update_fields=["status"])
            _audit(org, request.user, "directory.resumed", conn)
            messages.success(request, "Automatic sync resumed.")
        elif act == "disconnect":
            Membership.objects.filter(organization=org, entra_managed=True).update(entra_managed=False)
            _audit(org, request.user, "directory.disconnected", conn, tenant=conn.tenant_id)
            conn.delete()
            messages.success(
                request,
                "Disconnected. Members stay as they are and are now managed by hand. To remove Clavium's access completely, "
                "delete the Clavium app under Enterprise applications in the Microsoft Entra admin center.",
            )
        else:
            messages.error(request, "Unknown action.")
    except GraphError as e:
        messages.error(request, str(e))
    return back


def _report(request, result):
    if result.get("error"):
        messages.error(request, f"Sync failed, nothing was changed: {result['error']}")
        return
    if result.get("skipped"):
        messages.info(request, f"Nothing to sync: {result['skipped']}.")
        return
    parts = [f"{len(result[k])} {label}" for k, label in (("added", "added"), ("linked", "linked"), ("reactivated", "returned"), ("promoted", "made admin"), ("demoted", "made member"), ("removed", "removed")) if result.get(k)]
    text = "Sync complete: " + (", ".join(parts) if parts else "no changes") + "."
    if result.get("held"):
        messages.error(request, f"{text} {len(result['not_in_directory'])} removal(s) were held for safety. Review them below.")
    else:
        messages.success(request, text)
