from django.contrib import admin

from .models import SyncItem, SyncVault


@admin.register(SyncVault)
class SyncVaultAdmin(admin.ModelAdmin):
    list_display = ("account", "vault_id", "keyring_revision", "counter", "updated_at")
    readonly_fields = ("account", "vault_id", "keyring_header", "keyring_revision", "counter")


@admin.register(SyncItem)
class SyncItemAdmin(admin.ModelAdmin):
    list_display = ("sync_vault", "item_id", "revision", "deleted", "size_bytes", "updated_at")
    exclude = ("ciphertext",)
