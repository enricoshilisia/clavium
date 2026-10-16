from django.contrib import admin

from .models import AuditLogEntry, Membership, Organization


@admin.register(Organization)
class OrganizationAdmin(admin.ModelAdmin):
    list_display = ["name", "created_by", "created_at"]


@admin.register(Membership)
class MembershipAdmin(admin.ModelAdmin):
    list_display = ["account", "organization", "role", "joined_at", "removed_at"]
    list_filter = ["role", "organization"]


@admin.register(AuditLogEntry)
class AuditLogEntryAdmin(admin.ModelAdmin):
    list_display = ["action", "object_type", "actor", "organization", "created_at"]
    list_filter = ["action", "organization"]

    def has_change_permission(self, request, obj=None):
        return False

    def has_delete_permission(self, request, obj=None):
        return False
