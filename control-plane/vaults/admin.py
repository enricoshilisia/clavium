from django.contrib import admin

from .models import SharedVault, SharedVaultSnapshot, VaultSnapshot, WrappedVaultKey


@admin.register(VaultSnapshot)
class VaultSnapshotAdmin(admin.ModelAdmin):
    list_display = ["account", "version", "size_bytes", "uploaded_by", "created_at"]
    list_filter = ["account"]


@admin.register(SharedVault)
class SharedVaultAdmin(admin.ModelAdmin):
    list_display = ["name", "organization", "created_by", "created_at"]
    list_filter = ["organization"]


@admin.register(WrappedVaultKey)
class WrappedVaultKeyAdmin(admin.ModelAdmin):
    list_display = ["shared_vault", "device", "granted_by", "created_at"]
    list_filter = ["shared_vault"]


@admin.register(SharedVaultSnapshot)
class SharedVaultSnapshotAdmin(admin.ModelAdmin):
    list_display = ["shared_vault", "version", "size_bytes", "uploaded_by", "created_at"]
    list_filter = ["shared_vault"]
