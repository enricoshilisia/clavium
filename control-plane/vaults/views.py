import hashlib

from django.db import transaction
from rest_framework.response import Response
from rest_framework.views import APIView

from .models import VaultSnapshot
from .serializers import (
    SnapshotUploadSerializer,
    VaultSnapshotDetailSerializer,
    VaultSnapshotMetaSerializer,
)


class SnapshotListCreateView(APIView):
    def get(self, request):
        snapshots = request.user.vault_snapshots.all()
        return Response(VaultSnapshotMetaSerializer(snapshots, many=True).data)

    def post(self, request):
        serializer = SnapshotUploadSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        blob = serializer.validated_data["blob"]

        # Locks the account's existing rows for the duration of the
        # transaction, so two devices uploading at the same instant get
        # distinct, sequential versions instead of racing onto the same
        # number — the same "the ledger is authoritative, not in-memory
        # state" discipline a concurrent writer anywhere needs.
        with transaction.atomic():
            last_version = (
                VaultSnapshot.objects.select_for_update()
                .filter(account=request.user)
                .order_by("-version")
                .values_list("version", flat=True)
                .first()
            ) or 0

            snapshot = VaultSnapshot.objects.create(
                account=request.user,
                version=last_version + 1,
                blob=blob,
                sha256=hashlib.sha256(blob).hexdigest(),
                size_bytes=len(blob),
                uploaded_by=request.auth,
            )

        return Response(VaultSnapshotMetaSerializer(snapshot).data, status=201)


class SnapshotLatestView(APIView):
    def get(self, request):
        snapshot = request.user.vault_snapshots.order_by("-version").first()
        if snapshot is None:
            return Response({"detail": "no snapshot has been uploaded yet"}, status=404)
        return Response(VaultSnapshotDetailSerializer(snapshot).data)


class SnapshotDetailView(APIView):
    def get(self, request, version):
        snapshot = request.user.vault_snapshots.filter(version=version).first()
        if snapshot is None:
            return Response({"detail": "no such version"}, status=404)
        return Response(VaultSnapshotDetailSerializer(snapshot).data)
