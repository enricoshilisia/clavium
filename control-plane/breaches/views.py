from datetime import timedelta

from django.utils import timezone
from rest_framework.response import Response
from rest_framework.views import APIView

from . import hibp, service
from .models import EmailBreachStatus


def _payload(account):
    st = EmailBreachStatus.objects.filter(account=account).first()
    monitored = service.monitored_accounts().filter(id=account.id).exists()
    return {
        "available": hibp.configured(),
        "monitored": monitored,
        "opted_in": bool(st and st.opted_in),
        "checked_at": st.checked_at if st else None,
        "breaches": st.breaches if st else [],
    }


class MyBreachesView(APIView):
    """Email breach status for the signed-in account."""

    def get(self, request):
        return Response(_payload(request.user))

    def post(self, request):
        """Turn checking of your own address on or off; turning it on
        checks straight away (at most once an hour)."""
        if not hibp.configured():
            return Response({"detail": "Email breach checks are not set up on this server yet."}, status=404)
        st, _ = EmailBreachStatus.objects.get_or_create(account=request.user)
        st.opted_in = bool(request.data.get("enabled", True))
        st.save(update_fields=["opted_in"])
        if st.opted_in and (st.checked_at is None or timezone.now() - st.checked_at > timedelta(hours=1)):
            try:
                service.check(request.user, notify=False)
            except hibp.HibpError as e:
                return Response({**_payload(request.user), "detail": str(e)}, status=502)
        return Response(_payload(request.user))
