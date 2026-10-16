import base64

from rest_framework import serializers

from .models import SharedVault, SharedVaultSnapshot, VaultSnapshot, WrappedVaultKey

# A generous ceiling for a credential vault, which is small text records,
# not media — refusing an absurdly large upload outright beats discovering
# a bug (or an abuse case) by filling the database one blob at a time.
MAX_BLOB_BYTES = 25 * 1024 * 1024


class SnapshotUploadSerializer(serializers.Serializer):
    blob = serializers.CharField(write_only=True)

    def validate_blob(self, value):
        try:
            raw = base64.b64decode(value, validate=True)
        except Exception as exc:
            raise serializers.ValidationError("blob is not valid base64") from exc

        if len(raw) > MAX_BLOB_BYTES:
            raise serializers.ValidationError(
                f"blob is {len(raw)} bytes, over the {MAX_BLOB_BYTES} byte limit"
            )
        if raw[: len(VaultSnapshot.MAGIC)] != VaultSnapshot.MAGIC:
            raise serializers.ValidationError(
                "this does not look like a Clavium vault file (wrong magic header)"
            )
        return raw


class VaultSnapshotMetaSerializer(serializers.ModelSerializer):
    uploaded_by_device = serializers.CharField(source="uploaded_by.name", default=None)

    class Meta:
        model = VaultSnapshot
        fields = ["id", "version", "sha256", "size_bytes", "uploaded_by_device", "created_at"]


class VaultSnapshotDetailSerializer(VaultSnapshotMetaSerializer):
    blob = serializers.SerializerMethodField()

    class Meta(VaultSnapshotMetaSerializer.Meta):
        fields = VaultSnapshotMetaSerializer.Meta.fields + ["blob"]

    def get_blob(self, obj):
        return base64.b64encode(bytes(obj.blob)).decode()


class SharedVaultCreateSerializer(serializers.Serializer):
    name = serializers.CharField(max_length=200)


class SharedVaultSerializer(serializers.ModelSerializer):
    created_by_email = serializers.EmailField(source="created_by.email", read_only=True)
    grant_count = serializers.IntegerField(source="wrapped_keys.count", read_only=True)

    class Meta:
        model = SharedVault
        fields = ["id", "name", "created_by_email", "grant_count", "created_at"]


class GrantableDeviceSerializer(serializers.Serializer):
    """A member device with a public key on file — eligible to be granted
    a wrapped copy of a shared vault's key. `public_key` is included
    because the granting client needs it to perform the wrap itself; the
    server never does this wrapping (it would need the raw key to do so).
    """

    device_id = serializers.UUIDField(source="id")
    account_email = serializers.EmailField(source="account.email")
    device_name = serializers.CharField(source="name")
    public_key = serializers.CharField()
    has_grant = serializers.SerializerMethodField()

    def get_has_grant(self, device):
        granted_device_ids = self.context.get("granted_device_ids", set())
        return device.id in granted_device_ids


class GrantCreateSerializer(serializers.Serializer):
    device_id = serializers.UUIDField()
    wrapped_key = serializers.CharField()

    def validate_wrapped_key(self, value):
        try:
            return base64.b64decode(value, validate=True)
        except Exception as exc:
            raise serializers.ValidationError("wrapped_key is not valid base64") from exc


class WrappedVaultKeySerializer(serializers.ModelSerializer):
    wrapped_key = serializers.SerializerMethodField()
    device_name = serializers.CharField(source="device.name", read_only=True)
    account_email = serializers.EmailField(source="device.account.email", read_only=True)

    class Meta:
        model = WrappedVaultKey
        fields = ["id", "device_name", "account_email", "wrapped_key", "created_at"]

    def get_wrapped_key(self, obj):
        return base64.b64encode(bytes(obj.wrapped_key)).decode()


class SharedSnapshotUploadSerializer(serializers.Serializer):
    blob = serializers.CharField(write_only=True)

    def validate_blob(self, value):
        try:
            raw = base64.b64decode(value, validate=True)
        except Exception as exc:
            raise serializers.ValidationError("blob is not valid base64") from exc

        if len(raw) > MAX_BLOB_BYTES:
            raise serializers.ValidationError(
                f"blob is {len(raw)} bytes, over the {MAX_BLOB_BYTES} byte limit"
            )
        if raw[: len(SharedVaultSnapshot.MAGIC)] != SharedVaultSnapshot.MAGIC:
            raise serializers.ValidationError("this does not look like a Clavium vault file")
        if len(raw) > 4 and raw[4] != SharedVaultSnapshot.FORMAT_VERSION:
            raise serializers.ValidationError(
                "this looks like a personal (password-sealed) vault, not a shared vault — "
                "a shared vault must be sealed with Vault::seal_with_raw_key"
            )
        return raw


class SharedVaultSnapshotMetaSerializer(serializers.ModelSerializer):
    uploaded_by_device = serializers.CharField(source="uploaded_by.name", default=None)

    class Meta:
        model = SharedVaultSnapshot
        fields = ["id", "version", "sha256", "size_bytes", "uploaded_by_device", "created_at"]


class SharedVaultSnapshotDetailSerializer(SharedVaultSnapshotMetaSerializer):
    blob = serializers.SerializerMethodField()

    class Meta(SharedVaultSnapshotMetaSerializer.Meta):
        fields = SharedVaultSnapshotMetaSerializer.Meta.fields + ["blob"]

    def get_blob(self, obj):
        return base64.b64encode(bytes(obj.blob)).decode()
