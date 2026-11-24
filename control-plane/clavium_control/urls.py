from django.contrib import admin
from django.http import JsonResponse
from django.urls import include, path

from accounts.views import verify_email_page
from entra.notifications import notify as entra_notify
from shares.views import share_page
from vaults.urls import shared_vault_urlpatterns

urlpatterns = [
    path("admin/", admin.site.urls),
    path("api/health/", lambda request: JsonResponse({"status": "ok"})),
    path("verify-email/", verify_email_page, name="verify-email"),
    path("api/accounts/", include("accounts.urls")),
    path("api/vaults/", include("vaults.urls")),
    path("api/shares/", include("shares.urls")),
    path("s/<uuid:share_id>", share_page, name="share-page"),
    path("api/teams/", include("teams.urls")),
    path("api/sync/", include("sync.urls")),
    path("scim/v2/", include("scim.urls")),
    path("api/entra/notify/", entra_notify, name="entra-notify"),
    path("api/link/", include("link.urls")),
    path("console/", include("console.urls")),
    path("api/orgs/", include("orgs.urls")),
    # Shared-vault endpoints nest under the same /api/orgs/<org_id>/ prefix
    # as membership and the audit log, even though the models live in the
    # vaults app — see the comment in vaults/urls.py.
    path("api/orgs/", include(shared_vault_urlpatterns)),
]
