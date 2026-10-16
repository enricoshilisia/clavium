from django.contrib import admin

from .models import Account, Device, DeviceToken


@admin.register(Account)
class AccountAdmin(admin.ModelAdmin):
    list_display = ["email", "display_name", "is_active", "is_staff", "created_at"]
    search_fields = ["email", "display_name"]


@admin.register(Device)
class DeviceAdmin(admin.ModelAdmin):
    list_display = ["name", "account", "platform", "created_at", "last_seen_at", "revoked_at"]
    list_filter = ["platform"]
    search_fields = ["name", "account__email"]


@admin.register(DeviceToken)
class DeviceTokenAdmin(admin.ModelAdmin):
    list_display = ["device", "created_at", "revoked_at"]
