from django.utils import timezone
from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import AuthenticationFailed

from .models import DeviceToken


class DeviceTokenAuthentication(BaseAuthentication):
    """`Authorization: Bearer <token>` — a device's own bearer credential.

    `request.user` becomes the account, `request.auth` becomes the device
    itself, so a view that needs to know *which device* called it (vault
    snapshot uploads record this) doesn't need a second lookup.
    """

    keyword = "Bearer"

    def authenticate(self, request):
        header = request.META.get("HTTP_AUTHORIZATION", "")
        if not header.startswith(f"{self.keyword} "):
            return None

        raw = header[len(self.keyword) + 1 :].strip()
        if not raw:
            raise AuthenticationFailed("empty bearer token")

        token = DeviceToken.authenticate(raw)
        if token is None:
            raise AuthenticationFailed("invalid or revoked device token")

        token.device.last_seen_at = timezone.now()
        token.device.save(update_fields=["last_seen_at"])

        return (token.device.account, token.device)

    def authenticate_header(self, request):
        # Declaring this is what makes a missing/invalid token a 401
        # ("not authenticated") rather than DRF's 403 fallback ("you are
        # authenticated but not allowed") — the two mean different things
        # to a client deciding whether to prompt for credentials again.
        return self.keyword
