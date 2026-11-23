"""SCIM 2.0 (RFC 7643/7644) user provisioning for one organization per
bearer token. Tested against the request shapes Microsoft Entra ID sends
(including its string booleans and capitalised operation names).

- Create  -> account (no password yet) + membership + invite link
- active:false / DELETE -> offboard: membership removed, shared-vault
  access revoked, every device signed out
- active:true -> membership restored (devices must sign in again)
"""

import json

from django.db import transaction
from django.http import JsonResponse
from django.utils import timezone
from django.views.decorators.csrf import csrf_exempt

from accounts.models import Account
from orgs.models import AuditLogEntry, Invite, Membership, ScimToken
from orgs.services import offboard

CORE = "urn:ietf:params:scim:schemas:core:2.0:User"
LIST = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
ERROR = "urn:ietf:params:scim:api:messages:2.0:Error"
PATCH = "urn:ietf:params:scim:api:messages:2.0:PatchOp"


def _err(status, detail, scim_type=None):
    body = {"schemas": [ERROR], "status": str(status), "detail": detail}
    if scim_type:
        body["scimType"] = scim_type
    return JsonResponse(body, status=status, content_type="application/scim+json")


def _ok(body, status=200):
    return JsonResponse(body, status=status, content_type="application/scim+json")


def _truthy(v):
    if isinstance(v, str):
        return v.strip().lower() == "true"
    return bool(v)


def _auth(request):
    header = request.META.get("HTTP_AUTHORIZATION", "")
    if not header.startswith("Bearer "):
        return None
    token = ScimToken.authenticate(header[7:].strip())
    if token:
        token.last_used_at = timezone.now()
        token.save(update_fields=["last_used_at"])
    return token


def _user(request, m: Membership):
    a = m.account
    return {
        "schemas": [CORE],
        "id": str(m.id),
        "externalId": m.external_id or None,
        "userName": a.email,
        "displayName": a.display_name or a.email,
        "name": {"formatted": a.display_name or a.email},
        "emails": [{"value": a.email, "type": "work", "primary": True}],
        "active": m.removed_at is None,
        "meta": {
            "resourceType": "User",
            "created": m.joined_at.isoformat(),
            "lastModified": (m.removed_at or m.joined_at).isoformat(),
            "location": request.build_absolute_uri(f"/scim/v2/Users/{m.id}"),
        },
    }


def _body(request):
    try:
        return json.loads(request.body or b"{}")
    except ValueError:
        return None


def _email_from(body):
    email = body.get("userName") or ""
    for e in body.get("emails") or []:
        if e.get("primary") or not email:
            email = e.get("value") or email
    return email.strip().lower()


def _display_from(body):
    if body.get("displayName"):
        return body["displayName"]
    name = body.get("name") or {}
    return name.get("formatted") or " ".join(x for x in (name.get("givenName"), name.get("familyName")) if x)


def _set_active(m, active, token, actor_label):
    org = token.organization
    if active and m.removed_at is not None:
        m.removed_at = None
        m.save(update_fields=["removed_at"])
        m.account.is_active = True
        m.account.save(update_fields=["is_active"])
        AuditLogEntry.record(organization=org, actor=None, action="member.reactivated", obj=m, source="scim", member_email=m.account.email)
    elif not active and m.removed_at is None:
        offboard(org, m, None, revoke_devices=True, source=f"scim:{actor_label}")
        if m.scim_managed and not m.account.memberships.filter(removed_at__isnull=True).exists():
            m.account.is_active = False
            m.account.save(update_fields=["is_active"])


@csrf_exempt
def service_provider_config(request):
    if not _auth(request):
        return _err(401, "invalid SCIM token")
    return _ok(
        {
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"],
            "patch": {"supported": True},
            "bulk": {"supported": False, "maxOperations": 0, "maxPayloadSize": 0},
            "filter": {"supported": True, "maxResults": 200},
            "changePassword": {"supported": False},
            "sort": {"supported": False},
            "etag": {"supported": False},
            "authenticationSchemes": [{"type": "oauthbearertoken", "name": "Bearer token", "description": "Token from the Clavium console"}],
        }
    )


@csrf_exempt
def users(request):
    token = _auth(request)
    if not token:
        return _err(401, "invalid SCIM token")
    org = token.organization

    if request.method == "GET":
        qs = Membership.objects.filter(organization=org).select_related("account").order_by("joined_at")
        flt = request.GET.get("filter", "")
        if flt:
            parts = flt.split(" eq ", 1)
            if len(parts) != 2:
                return _err(400, "only 'eq' filters are supported", "invalidFilter")
            attr, value = parts[0].strip(), parts[1].strip().strip('"')
            if attr in ("userName", "emails.value", 'emails[type eq "work"].value'):
                qs = qs.filter(account__email__iexact=value)
            elif attr == "externalId":
                qs = qs.filter(external_id=value)
            else:
                return _err(400, f"filtering on {attr} is not supported", "invalidFilter")
        total = qs.count()
        start = max(int(request.GET.get("startIndex", 1) or 1), 1)
        count = min(int(request.GET.get("count", 100) or 100), 200)
        page = list(qs[start - 1 : start - 1 + count])
        return _ok({"schemas": [LIST], "totalResults": total, "startIndex": start, "itemsPerPage": len(page), "Resources": [_user(request, m) for m in page]})

    if request.method == "POST":
        body = _body(request)
        if body is None:
            return _err(400, "invalid JSON", "invalidSyntax")
        email = _email_from(body)
        if not email or "@" not in email:
            return _err(400, "userName (an email address) is required", "invalidValue")
        with transaction.atomic():
            account = Account.objects.filter(email__iexact=email).first()
            created_account = account is None
            if created_account:
                account = Account.objects.create(email=email, display_name=_display_from(body)[:200])
                account.set_unusable_password()
                account.save()
            m = Membership.objects.filter(organization=org, account=account).first()
            if m and m.removed_at is None:
                return _err(409, "user already exists in this organization", "uniqueness")
            if m:
                m.removed_at = None
            else:
                m = Membership(organization=org, account=account, role=Membership.Role.MEMBER)
            m.external_id = str(body.get("externalId") or "")[:255]
            m.scim_managed = True
            m.save()
            invite_url = None
            if not account.has_usable_password():
                _, raw = Invite.issue(org, account)
                invite_url = request.build_absolute_uri(f"/console/invite/{raw}/")
            AuditLogEntry.record(
                organization=org, actor=None, action="member.provisioned", obj=m, source="scim",
                member_email=email, new_account=created_account,
            )
            if not _truthy(body.get("active", True)):
                _set_active(m, False, token, token.label)
        out = _user(request, m)
        if invite_url:
            # Not part of the SCIM schema; shown in the console as well.
            out["urn:clavium:invite"] = {"url": invite_url}
        return _ok(out, status=201)

    return _err(405, "method not allowed")


@csrf_exempt
def user_detail(request, member_id):
    token = _auth(request)
    if not token:
        return _err(401, "invalid SCIM token")
    m = Membership.objects.select_related("account").filter(organization=token.organization, id=member_id).first()
    if not m:
        return _err(404, "user not found")

    if request.method == "GET":
        return _ok(_user(request, m))

    if request.method == "DELETE":
        _set_active(m, False, token, token.label)
        return _no_content()

    body = _body(request)
    if body is None:
        return _err(400, "invalid JSON", "invalidSyntax")

    if request.method == "PUT":
        name = _display_from(body)
        if name:
            m.account.display_name = name[:200]
            m.account.save(update_fields=["display_name"])
        if "externalId" in body:
            m.external_id = str(body.get("externalId") or "")[:255]
            m.save(update_fields=["external_id"])
        _set_active(m, _truthy(body.get("active", True)), token, token.label)
        m.refresh_from_db()
        return _ok(_user(request, m))

    if request.method == "PATCH":
        for op in body.get("Operations", []):
            kind = str(op.get("op", "")).lower()
            path = op.get("path")
            value = op.get("value")
            if kind not in ("replace", "add"):
                continue
            changes = {path: value} if path else (value if isinstance(value, dict) else {})
            for key, v in changes.items():
                if key == "active":
                    _set_active(m, _truthy(v), token, token.label)
                elif key in ("displayName", "name.formatted"):
                    m.account.display_name = str(v)[:200]
                    m.account.save(update_fields=["display_name"])
                elif key == "externalId":
                    m.external_id = str(v)[:255]
                    m.save(update_fields=["external_id"])
        m.refresh_from_db()
        return _ok(_user(request, m))

    return _err(405, "method not allowed")


def _no_content():
    from django.http import HttpResponse

    return HttpResponse(status=204)


@csrf_exempt
def groups(request):
    if not _auth(request):
        return _err(401, "invalid SCIM token")
    return _ok({"schemas": [LIST], "totalResults": 0, "startIndex": 1, "itemsPerPage": 0, "Resources": []})
