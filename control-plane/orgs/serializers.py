from rest_framework import serializers

from .models import AuditLogEntry, Membership, Organization


class OrganizationSerializer(serializers.ModelSerializer):
    my_role = serializers.SerializerMethodField()

    class Meta:
        model = Organization
        fields = ["id", "name", "created_at", "my_role"]

    def get_my_role(self, obj):
        membership = self.context.get("memberships", {}).get(obj.id)
        return membership.role if membership else None


class OrganizationCreateSerializer(serializers.Serializer):
    name = serializers.CharField(max_length=200)


class MembershipSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(source="account.email", read_only=True)

    class Meta:
        model = Membership
        fields = ["id", "email", "role", "joined_at", "removed_at"]


class MemberAddSerializer(serializers.Serializer):
    email = serializers.EmailField()
    role = serializers.ChoiceField(choices=Membership.Role.choices, default=Membership.Role.MEMBER)


class AuditLogEntrySerializer(serializers.ModelSerializer):
    actor_email = serializers.EmailField(source="actor.email", read_only=True, default=None)

    class Meta:
        model = AuditLogEntry
        fields = ["id", "actor_email", "action", "object_type", "object_id", "metadata", "created_at"]
