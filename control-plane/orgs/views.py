from django.shortcuts import get_object_or_404
from django.utils import timezone
from rest_framework.response import Response
from rest_framework.views import APIView

from accounts.models import Account

from .models import AuditLogEntry, HealthSnapshot, Membership, Organization, OrgPolicy
from .services import is_last_owner, offboard
from .serializers import (
    AuditLogEntrySerializer,
    MemberAddSerializer,
    MembershipSerializer,
    OrganizationCreateSerializer,
    OrganizationSerializer,
)


def _active_membership(organization, account):
    return Membership.objects.filter(
        organization=organization, account=account, removed_at__isnull=True
    ).first()


def _require_admin(organization, account):
    """`None` means allowed; anything else is the `Response` to return."""
    membership = _active_membership(organization, account)
    if membership is None:
        return Response({"detail": "not a member of this organization"}, status=404)
    if membership.role not in (Membership.Role.OWNER, Membership.Role.ADMIN):
        return Response({"detail": "owner or admin role required"}, status=403)
    return None


class OrganizationListCreateView(APIView):
    def get(self, request):
        memberships = {
            m.organization_id: m
            for m in Membership.objects.filter(account=request.user, removed_at__isnull=True)
        }
        orgs = Organization.objects.filter(id__in=memberships.keys())
        serializer = OrganizationSerializer(orgs, many=True, context={"memberships": memberships})
        return Response(serializer.data)

    def post(self, request):
        serializer = OrganizationCreateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        org = Organization.objects.create(name=serializer.validated_data["name"], created_by=request.user)
        membership = Membership.objects.create(
            organization=org, account=request.user, role=Membership.Role.OWNER, added_by=request.user
        )
        AuditLogEntry.record(organization=org, actor=request.user, action="organization.created", obj=org)

        context = {"memberships": {org.id: membership}}
        return Response(OrganizationSerializer(org, context=context).data, status=201)


class MembershipListView(APIView):
    def get(self, request, org_id):
        org = get_object_or_404(Organization, id=org_id)
        if _active_membership(org, request.user) is None:
            return Response({"detail": "not a member of this organization"}, status=404)

        members = Membership.objects.filter(organization=org, removed_at__isnull=True).select_related(
            "account"
        )
        return Response(MembershipSerializer(members, many=True).data)

    def post(self, request, org_id):
        org = get_object_or_404(Organization, id=org_id)
        denied = _require_admin(org, request.user)
        if denied:
            return denied

        serializer = MemberAddSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data

        target = Account.objects.filter(email__iexact=data["email"]).first()
        if target is None:
            return Response(
                {"detail": "no Clavium account with that email exists yet"}, status=404
            )

        existing = Membership.objects.filter(organization=org, account=target).first()
        if existing is not None and existing.is_active:
            return Response({"detail": "already a member"}, status=400)

        if existing is not None:
            # Re-adding someone previously offboarded: reactivate the same
            # row rather than a fresh one, so their membership history
            # (and the audit trail pointing at it) stays one continuous
            # thread instead of fragmenting across rows.
            existing.removed_at = None
            existing.role = data["role"]
            existing.added_by = request.user
            existing.save(update_fields=["removed_at", "role", "added_by"])
            membership = existing
        else:
            membership = Membership.objects.create(
                organization=org, account=target, role=data["role"], added_by=request.user
            )

        AuditLogEntry.record(
            organization=org,
            actor=request.user,
            action="member.added",
            obj=membership,
            member_email=target.email,
            role=data["role"],
        )
        return Response(MembershipSerializer(membership).data, status=201)


class MemberRemoveView(APIView):
    """Offboarding. The membership flag flip is the easy half; the half
    that actually matters is pulling every one of this account's devices
    out of every shared vault's key hierarchy in this organization, right
    now, not on the next sync — an offboarded member with a stale wrapped
    key on a laptop they still own is not offboarded.
    """

    def post(self, request, org_id, membership_id):
        org = get_object_or_404(Organization, id=org_id)
        denied = _require_admin(org, request.user)
        if denied:
            return denied

        membership = get_object_or_404(Membership, id=membership_id, organization=org)
        if not membership.is_active:
            return Response({"detail": "already removed"}, status=400)
        if is_last_owner(org, membership):
            return Response({"detail": "cannot remove the organization's last owner"}, status=400)
        result = offboard(
            org,
            membership,
            request.user,
            revoke_devices=bool(request.data.get("revoke_devices", False)),
            source="api",
        )
        return Response(result, status=200)


class AuditLogView(APIView):
    def get(self, request, org_id):
        org = get_object_or_404(Organization, id=org_id)
        if _active_membership(org, request.user) is None:
            return Response({"detail": "not a member of this organization"}, status=404)

        entries = org.audit_entries.all()[:200]
        return Response(AuditLogEntrySerializer(entries, many=True).data)


class MyPolicyView(APIView):
    """The effective policy for the signed-in account (strictest across all
    of its organizations). Apps fetch this after each sync."""

    def get(self, request):
        return Response(OrgPolicy.effective_for(request.user))


class OrgPolicyView(APIView):
    FIELDS = ("min_master_password_length", "max_auto_lock_minutes", "allow_export", "require_recovery_key")

    def get(self, request, org_id):
        org = get_object_or_404(Organization, id=org_id)
        if _active_membership(org, request.user) is None:
            return Response({"detail": "not a member of this organization"}, status=404)
        policy, _ = OrgPolicy.objects.get_or_create(organization=org)
        return Response(policy.as_dict())

    def put(self, request, org_id):
        org = get_object_or_404(Organization, id=org_id)
        denied = _require_admin(org, request.user)
        if denied:
            return denied
        policy, _ = OrgPolicy.objects.get_or_create(organization=org)
        errors = {}
        for f in self.FIELDS:
            if f not in request.data:
                continue
            v = request.data[f]
            if f in ("allow_export", "require_recovery_key"):
                if not isinstance(v, bool):
                    errors[f] = "must be true or false"
                    continue
            else:
                if not isinstance(v, int) or v < 0 or (f == "min_master_password_length" and not 8 <= v <= 128) or v > 1440:
                    errors[f] = "out of range"
                    continue
            setattr(policy, f, v)
        if errors:
            return Response(errors, status=400)
        policy.updated_by = request.user
        policy.save()
        AuditLogEntry.record(organization=org, actor=request.user, action="policy.updated", obj=policy, **policy.as_dict())
        return Response(policy.as_dict())


class HealthReportView(APIView):
    """An app reports its vault's aggregate health. Counts only."""

    def post(self, request):
        fields = ("score", "total", "weak", "reused", "old", "without_totp")
        data = {}
        for f in fields:
            v = request.data.get(f)
            if not isinstance(v, int) or v < 0 or v > 1_000_000 or (f == "score" and v > 100):
                return Response({f: "must be a non-negative integer"}, status=400)
            data[f] = v
        data["has_recovery_key"] = bool(request.data.get("has_recovery_key", False))
        HealthSnapshot.objects.update_or_create(account=request.user, defaults=data)
        return Response(status=204)
