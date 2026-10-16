from django.urls import path

from . import shared_views, views

urlpatterns = [
    path("snapshots/", views.SnapshotListCreateView.as_view(), name="snapshot-list-create"),
    path("snapshots/latest/", views.SnapshotLatestView.as_view(), name="snapshot-latest"),
    path("snapshots/<int:version>/", views.SnapshotDetailView.as_view(), name="snapshot-detail"),
]

# Organization-scoped shared-vault endpoints. Nested under /api/orgs/ at
# the project level (see clavium_control/urls.py) rather than living in
# orgs/urls.py — the models are a vaults concern (SharedVault,
# WrappedVaultKey), orgs only owns membership and the audit log.
shared_vault_urlpatterns = [
    path(
        "<uuid:org_id>/shared-vaults/",
        shared_views.SharedVaultListCreateView.as_view(),
        name="shared-vault-list-create",
    ),
    path(
        "<uuid:org_id>/shared-vaults/<uuid:vault_id>/devices/",
        shared_views.GrantableDevicesView.as_view(),
        name="shared-vault-grantable-devices",
    ),
    path(
        "<uuid:org_id>/shared-vaults/<uuid:vault_id>/grants/",
        shared_views.GrantListCreateView.as_view(),
        name="shared-vault-grant-list-create",
    ),
    path(
        "<uuid:org_id>/shared-vaults/<uuid:vault_id>/grants/mine/",
        shared_views.GrantMineView.as_view(),
        name="shared-vault-grant-mine",
    ),
    path(
        "<uuid:org_id>/shared-vaults/<uuid:vault_id>/grants/<uuid:device_id>/",
        shared_views.GrantRevokeView.as_view(),
        name="shared-vault-grant-revoke",
    ),
    path(
        "<uuid:org_id>/shared-vaults/<uuid:vault_id>/snapshots/",
        shared_views.SharedSnapshotListCreateView.as_view(),
        name="shared-vault-snapshot-list-create",
    ),
    path(
        "<uuid:org_id>/shared-vaults/<uuid:vault_id>/snapshots/latest/",
        shared_views.SharedSnapshotLatestView.as_view(),
        name="shared-vault-snapshot-latest",
    ),
]
