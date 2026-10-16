import hashlib

from django.db import transaction
from django.shortcuts import get_object_or_404
from rest_framework.response import Response
from rest_framework.views import APIView

from accounts.models import Device
from orgs.models import AuditLogEntry, Membership, Organization

from .models import SharedVault, SharedVaultSnapshot, WrappedVaultKey
from .serializers import (
    GrantableDeviceSerializer,
    GrantCreateSerializer,
    SharedSnapshotUploadSerializer,
    SharedVaultCreateSerializer,
    SharedVaultSerializer,
    SharedVaultSnapshotDetailSerializer,
    SharedVaultSnapshotMetaSerializer,
    WrappedVaultKeySerializer,
)


def _require_active_member(organization, account):
    membership = Membership.objects.filter(
        organization=organization, account=account, removed_at__isnull=True
    ).first()
    if membership is None:
        return None, Response({"detail": "not a member of this organization"}, status=404)
    return membership, None


def _require_grant(shared_vault, device):
    """A device may only touch a shared vault's blob if it currently holds
    a wrapped key for it — org membership alone is not enough, because
    membership can outlive a device's own grant (a device added before
    this vault existed, or one an admin deliberately left out).
    """
    return WrappedVaultKey.objects.filter(shared_vault=shared_vault, device=device).exists()


class SharedVaultListCreateView(APIView):
    def get(self, request, org_id):
        org = get_object_or_404(Organization, id=org_id)
        _, denied = _require_active_member(org, request.user)
        if denied:
            return denied

        vaults = org.shared_vaults.all().order_by("name")
        return Response(SharedVaultSerializer(vaults, many=True).data)

    def post(self, request, org_id):
        org = get_object_or_404(Organization, id=org_id)
        _, denied = _require_active_member(org, request.user)
        if denied:
            return denied

        serializer = SharedVaultCreateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        shared_vault = SharedVault.objects.create(
            organization=org, name=serializer.validated_data["name"], created_by=request.user
        )
        AuditLogEntry.record(
            organization=org, actor=request.user, action="shared_vault.created", obj=shared_vault,
            name=shared_vault.name,
        )
        return Response(SharedVaultSerializer(shared_vault).data, status=201)


class GrantableDevicesView(APIView):
    """Every device belonging to an active org member that has a public
    key on file — what a granting client needs to decide who to wrap the
    vault key for next.
    """

    def get(self, request, org_id, vault_id):
        org = get_object_or_404(Organization, id=org_id)
        _, denied = _require_active_member(org, request.user)
        if denied:
            return denied
        shared_vault = get_object_or_404(SharedVault, id=vault_id, organization=org)

        member_account_ids = Membership.objects.filter(
            organization=org, removed_at__isnull=True
        ).values_list("account_id", flat=True)
        devices = Device.objects.filter(
            account_id__in=member_account_ids, revoked_at__isnull=True
        ).exclude(public_key="").select_related("account")

        granted_device_ids = set(
            WrappedVaultKey.objects.filter(shared_vault=shared_vault).values_list("device_id", flat=True)
        )
        serializer = GrantableDeviceSerializer(
            devices, many=True, context={"granted_device_ids": granted_device_ids}
        )
        return Response(serializer.data)


class GrantListCreateView(APIView):
    def get(self, request, org_id, vault_id):
        org = get_object_or_404(Organization, id=org_id)
        _, denied = _require_active_member(org, request.user)
        if denied:
            return denied
        shared_vault = get_object_or_404(SharedVault, id=vault_id, organization=org)

        grants = shared_vault.wrapped_keys.select_related("device", "device__account")
        return Response(WrappedVaultKeySerializer(grants, many=True).data)

    def post(self, request, org_id, vault_id):
        org = get_object_or_404(Organization, id=org_id)
        _, denied = _require_active_member(org, request.user)
        if denied:
            return denied
        shared_vault = get_object_or_404(SharedVault, id=vault_id, organization=org)

        serializer = GrantCreateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data

        device = Device.objects.filter(id=data["device_id"], revoked_at__isnull=True).first()
        if device is None:
            return Response({"detail": "no such device"}, status=404)
        member, _ = _require_active_member(org, device.account)
        if member is None:
            return Response(
                {"detail": "that device's account is not an active member of this organization"},
                status=400,
            )

        grant, created = WrappedVaultKey.objects.update_or_create(
            shared_vault=shared_vault,
            device=device,
            defaults={"wrapped_key": data["wrapped_key"], "granted_by": request.user},
        )
        AuditLogEntry.record(
            organization=org,
            actor=request.user,
            action="vault_key.granted" if created else "vault_key.regranted",
            obj=grant,
            shared_vault=str(shared_vault.id),
            device=str(device.id),
            device_account_email=device.account.email,
        )
        return Response(WrappedVaultKeySerializer(grant).data, status=201 if created else 200)


class GrantMineView(APIView):
    """What a device calls with its own bearer token to fetch its wrapped
    copy of a shared vault's key — the one it can actually unwrap, using
    the private key that never left it.
    """

    def get(self, request, org_id, vault_id):
        org = get_object_or_404(Organization, id=org_id)
        shared_vault = get_object_or_404(SharedVault, id=vault_id, organization=org)
        grant = WrappedVaultKey.objects.filter(shared_vault=shared_vault, device=request.auth).first()
        if grant is None:
            return Response({"detail": "this device has not been granted access"}, status=404)
        return Response(WrappedVaultKeySerializer(grant).data)


class GrantRevokeView(APIView):
    def post(self, request, org_id, vault_id, device_id):
        org = get_object_or_404(Organization, id=org_id)
        denied = _require_admin_or_self(org, request, device_id)
        if denied:
            return denied
        shared_vault = get_object_or_404(SharedVault, id=vault_id, organization=org)

        grant = WrappedVaultKey.objects.filter(shared_vault=shared_vault, device_id=device_id).first()
        if grant is None:
            return Response({"detail": "no such grant"}, status=404)

        device_account_email = grant.device.account.email
        grant.delete()
        AuditLogEntry.record(
            organization=org,
            actor=request.user,
            action="vault_key.revoked",
            obj=shared_vault,
            device=str(device_id),
            device_account_email=device_account_email,
        )
        return Response(status=204)


def _require_admin_or_self(org, request, device_id):
    membership = Membership.objects.filter(
        organization=org, account=request.user, removed_at__isnull=True
    ).first()
    if membership is None:
        return Response({"detail": "not a member of this organization"}, status=404)
    if membership.role in (Membership.Role.OWNER, Membership.Role.ADMIN):
        return None
    # A member may always revoke their own device's grant (e.g. a lost
    # laptop they are pulling out of rotation themselves).
    if request.auth is not None and str(request.auth.id) == str(device_id):
        return None
    return Response({"detail": "owner, admin, or the device's own owner required"}, status=403)


class SharedSnapshotListCreateView(APIView):
    def get(self, request, org_id, vault_id):
        org = get_object_or_404(Organization, id=org_id)
        shared_vault = get_object_or_404(SharedVault, id=vault_id, organization=org)
        if not _require_grant(shared_vault, request.auth):
            return Response({"detail": "this device has not been granted access"}, status=403)

        snapshots = shared_vault.snapshots.all()
        return Response(SharedVaultSnapshotMetaSerializer(snapshots, many=True).data)

    def post(self, request, org_id, vault_id):
        org = get_object_or_404(Organization, id=org_id)
        shared_vault = get_object_or_404(SharedVault, id=vault_id, organization=org)
        if not _require_grant(shared_vault, request.auth):
            return Response({"detail": "this device has not been granted access"}, status=403)

        serializer = SharedSnapshotUploadSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        blob = serializer.validated_data["blob"]

        with transaction.atomic():
            last_version = (
                SharedVaultSnapshot.objects.select_for_update()
                .filter(shared_vault=shared_vault)
                .order_by("-version")
                .values_list("version", flat=True)
                .first()
            ) or 0

            snapshot = SharedVaultSnapshot.objects.create(
                shared_vault=shared_vault,
                version=last_version + 1,
                blob=blob,
                sha256=hashlib.sha256(blob).hexdigest(),
                size_bytes=len(blob),
                uploaded_by=request.auth,
            )

        return Response(SharedVaultSnapshotMetaSerializer(snapshot).data, status=201)


class SharedSnapshotLatestView(APIView):
    def get(self, request, org_id, vault_id):
        org = get_object_or_404(Organization, id=org_id)
        shared_vault = get_object_or_404(SharedVault, id=vault_id, organization=org)
        if not _require_grant(shared_vault, request.auth):
            return Response({"detail": "this device has not been granted access"}, status=403)

        snapshot = shared_vault.snapshots.order_by("-version").first()
        if snapshot is None:
            return Response({"detail": "no snapshot has been uploaded yet"}, status=404)
        return Response(SharedVaultSnapshotDetailSerializer(snapshot).data)
