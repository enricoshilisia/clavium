from django.contrib import admin
from django.http import JsonResponse
from django.urls import include, path

from vaults.urls import shared_vault_urlpatterns

urlpatterns = [
    path("admin/", admin.site.urls),
    path("api/health/", lambda request: JsonResponse({"status": "ok"})),
    path("api/accounts/", include("accounts.urls")),
    path("api/vaults/", include("vaults.urls")),
    path("api/orgs/", include("orgs.urls")),
    # Shared-vault endpoints nest under the same /api/orgs/<org_id>/ prefix
    # as membership and the audit log, even though the models live in the
    # vaults app — see the comment in vaults/urls.py.
    path("api/orgs/", include(shared_vault_urlpatterns)),
]
