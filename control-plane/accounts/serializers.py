from rest_framework import serializers

from .models import Account, Device


class RegisterSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True, min_length=10)
    display_name = serializers.CharField(required=False, allow_blank=True, default="")

    def validate_email(self, value):
        value = Account.objects.normalize_email(value)
        if Account.objects.filter(email__iexact=value).exists():
            raise serializers.ValidationError("an account with this email already exists")
        return value


class DeviceRegisterSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)
    client_device_id = serializers.CharField(max_length=64)
    name = serializers.CharField(max_length=200)
    platform = serializers.CharField(max_length=50, required=False, allow_blank=True, default="")
    # Base64 SPKI DER, only needed once a device wants to hold shared-vault
    # grants — a personal-vault-only device never has to send this.
    public_key = serializers.CharField(required=False, allow_blank=True, default="")


class DeviceSerializer(serializers.ModelSerializer):
    is_current = serializers.SerializerMethodField()

    class Meta:
        model = Device
        fields = [
            "id",
            "client_device_id",
            "name",
            "platform",
            "created_at",
            "last_seen_at",
            "revoked_at",
            "is_current",
        ]

    def get_is_current(self, obj):
        current = self.context.get("current_device")
        return current is not None and obj.id == current.id
