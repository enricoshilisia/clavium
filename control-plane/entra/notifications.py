"""Microsoft Graph change notifications: near-instant offboarding.

Each connected tenant has one subscription on /users. When anyone in the
tenant is updated or deleted, Microsoft POSTs to /api/entra/notify/. The
endpoint does no Graph work itself: it checks the shared secret
(clientState), marks the connection as due, and answers at once.
The timer (every minute) then runs the normal, safety-checked sync.

The notification is only a hint to look now. What changes is still
decided by reading the directory, so a forged or replayed notification
can at most cause an extra sync.
"""

import hashlib
import json
import secrets
from datetime import timedelta

from django.conf import settings
from django.http import HttpResponse, JsonResponse
from django.utils import timezone
from django.views.decorators.csrf import csrf_exempt

from . import graph
from .models import DirectoryConnection

LIFETIME = timedelta(days=7)  # Graph allows up to ~29 days for /users
RENEW_BEFORE = timedelta(days=2)
DEBOUNCE = timedelta(seconds=20)
SCHEDULED_EVERY = timedelta(minutes=15)


def _hash(v: str) -> str:
    return hashlib.sha256(v.encode()).hexdigest()


def notification_url() -> str:
    base = settings.CLAVIUM_PUBLIC_URL.rstrip("/")
    return f"{base}/api/entra/notify/" if base.startswith("https://") else ""


def ensure_subscription(conn: DirectoryConnection, client=None, now=None) -> str:
    """Create, renew or remove the subscription as the connection needs.
    Returns what happened, for logs."""
    now = now or timezone.now()
    wanted = conn.status != DirectoryConnection.Status.PAUSED and bool(conn.groups)
    if not wanted:
        if conn.subscription_id:
            remove_subscription(conn, client)
            return "removed"
        return "not needed"
    url = notification_url()
    if not url:
        if conn.subscription_error != "no public https address":
            conn.subscription_error = "no public https address"
            conn.save(update_fields=["subscription_error"])
        return "skipped: set CLAVIUM_PUBLIC_URL to an https address"
    try:
        client = client or graph.client_for(conn.tenant_id)
        if conn.subscription_id and conn.subscription_expires_at and conn.subscription_expires_at - now > RENEW_BEFORE:
            return "ok"
        if conn.subscription_id:
            try:
                client.renew_subscription(conn.subscription_id, now + LIFETIME)
                conn.subscription_expires_at = now + LIFETIME
                conn.subscription_error = ""
                conn.save(update_fields=["subscription_expires_at", "subscription_error"])
                return "renewed"
            except graph.GraphError as e:
                if e.status != 404:
                    raise
                # Gone on Microsoft's side (expired or removed): make a new one.
        state = secrets.token_urlsafe(32)
        sub = client.create_subscription(url, state, now + LIFETIME)
        conn.subscription_id = sub["id"]
        conn.subscription_expires_at = now + LIFETIME
        conn.client_state_hash = _hash(state)
        conn.subscription_error = ""
        conn.save(update_fields=["subscription_id", "subscription_expires_at", "client_state_hash", "subscription_error"])
        return "created"
    except graph.GraphError as e:
        conn.subscription_error = str(e)[:500]
        conn.save(update_fields=["subscription_error"])
        return f"error: {e}"


def remove_subscription(conn: DirectoryConnection, client=None) -> None:
    if conn.subscription_id:
        try:
            (client or graph.client_for(conn.tenant_id)).delete_subscription(conn.subscription_id)
        except graph.GraphError:
            pass  # expires on its own within LIFETIME
    conn.subscription_id = ""
    conn.subscription_expires_at = None
    conn.client_state_hash = ""
    if conn.pk:
        conn.save(update_fields=["subscription_id", "subscription_expires_at", "client_state_hash"])


def is_due(conn: DirectoryConnection, now=None) -> bool:
    now = now or timezone.now()
    if conn.sync_requested_at and now - conn.sync_requested_at >= DEBOUNCE:
        return True
    return conn.last_sync_at is None or now - conn.last_sync_at >= SCHEDULED_EVERY


@csrf_exempt
def notify(request):
    # Subscription handshake: echo the token as plain text within 10 s.
    token = request.GET.get("validationToken")
    if token is not None:
        return HttpResponse(token[:1024], content_type="text/plain")
    if request.method != "POST":
        return JsonResponse({"detail": "method not allowed"}, status=405)
    try:
        items = json.loads(request.body or b"{}").get("value", [])
    except (ValueError, AttributeError):
        return JsonResponse({"detail": "bad JSON"}, status=400)
    now = timezone.now()
    accepted = 0
    for item in items[:200] if isinstance(items, list) else []:
        sub_id = str(item.get("subscriptionId", ""))[:64]
        state = str(item.get("clientState", ""))
        if not sub_id or not state:
            continue
        conn = DirectoryConnection.objects.filter(subscription_id=sub_id).only("id", "client_state_hash", "tenant_id").first()
        if conn is None or not secrets.compare_digest(conn.client_state_hash, _hash(state)):
            continue
        if item.get("tenantId") and item["tenantId"] != conn.tenant_id:
            continue
        # Keep the earliest request so a stream of changes cannot postpone
        # the sync forever.
        DirectoryConnection.objects.filter(id=conn.id, sync_requested_at__isnull=True).update(sync_requested_at=now)
        accepted += 1
    # 202 for every well-formed batch, so probing reveals nothing.
    return HttpResponse(status=202)
