"""Email verification: prove an account's owner can read mail at its address.

Built to ship switched off. `CLAVIUM_EMAIL_VERIFICATION` decides behaviour:

  off       nothing is sent and nothing is enforced (the default)
  optional  a verification email goes out on sign-up and on request, and
            apps can show the status, but unverified accounts still sign in
  required  as optional, and an unverified account cannot sign in a new
            device or the admin console until it verifies

Devices that are already signed in keep working when the mode changes to
`required`, so turning it on never locks anyone out of a vault they are
using. Run `manage.py email_verification --mark-existing` first if
accounts created before the switch should count as verified.
"""

import secrets
from datetime import timedelta

from django.conf import settings
from django.core.mail import EmailMultiAlternatives
from django.db import transaction
from django.template.loader import render_to_string
from django.utils import timezone

from .models import Account, EmailVerification

OFF, OPTIONAL, REQUIRED = "off", "optional", "required"
CODE_LIFETIME = timedelta(minutes=30)
RESEND_COOLDOWN = timedelta(seconds=60)
MAX_PER_HOUR = 5


def mode() -> str:
    value = getattr(settings, "CLAVIUM_EMAIL_VERIFICATION", OFF)
    return value if value in (OFF, OPTIONAL, REQUIRED) else OFF


def enabled() -> bool:
    return mode() != OFF


def blocks_sign_in(account: Account) -> bool:
    return mode() == REQUIRED and not account.email_verified


def status(account: Account) -> dict:
    return {"email_verified": account.email_verified, "email_verification": mode()}


def _public_url(request) -> str:
    base = getattr(settings, "CLAVIUM_PUBLIC_URL", "")
    if base:
        return base.rstrip("/")
    return request.build_absolute_uri("/").rstrip("/") if request is not None else ""


class SendResult:
    SENT, ALREADY_VERIFIED, TOO_SOON, LIMIT, DISABLED = "sent", "verified", "too_soon", "limit", "disabled"


def send(account: Account, request=None) -> str:
    """Email a fresh code and link. Older unused challenges stop working."""
    if not enabled():
        return SendResult.DISABLED
    if account.email_verified:
        return SendResult.ALREADY_VERIFIED
    now = timezone.now()
    recent = account.email_verifications.filter(created_at__gte=now - timedelta(hours=1))
    if recent.filter(created_at__gte=now - RESEND_COOLDOWN).exists():
        return SendResult.TOO_SOON
    if recent.count() >= MAX_PER_HOUR:
        return SendResult.LIMIT

    code = f"{secrets.randbelow(1_000_000):06d}"
    token = secrets.token_urlsafe(32)
    with transaction.atomic():
        account.email_verifications.filter(used_at__isnull=True).update(used_at=now)
        EmailVerification.objects.create(
            account=account,
            email=account.email,
            code_hash=EmailVerification.hash_code(account.id, code),
            token_hash=EmailVerification.hash_link(token),
            expires_at=now + CODE_LIFETIME,
        )

    context = {
        "code": code,
        "link": f"{_public_url(request)}/verify-email/?t={token}",
        "minutes": int(CODE_LIFETIME.total_seconds() // 60),
        "name": account.display_name,
    }
    message = EmailMultiAlternatives(
        subject=f"Your Clavium verification code: {code}",
        body=render_to_string("accounts/email/verify.txt", context),
        from_email=settings.DEFAULT_FROM_EMAIL,
        to=[account.email],
    )
    message.attach_alternative(render_to_string("accounts/email/verify.html", context), "text/html")
    message.send()
    return SendResult.SENT


def _current(account: Account):
    return (
        account.email_verifications.filter(used_at__isnull=True, email=account.email, expires_at__gt=timezone.now())
        .order_by("-created_at")
        .first()
    )


def _mark_verified(account: Account, challenge: EmailVerification) -> None:
    now = timezone.now()
    challenge.used_at = now
    challenge.save(update_fields=["used_at"])
    account.email_verified_at = now
    account.save(update_fields=["email_verified_at"])


def verify_code(account: Account, code: str) -> bool:
    """Check a typed code. Five wrong tries burn the challenge."""
    with transaction.atomic():
        challenge = _current(account)
        if challenge is None:
            return False
        challenge = EmailVerification.objects.select_for_update().get(pk=challenge.pk)
        if challenge.used_at is not None or challenge.attempts >= EmailVerification.CODE_ATTEMPTS:
            return False
        expected = EmailVerification.hash_code(account.id, code.strip())
        if not secrets.compare_digest(expected, challenge.code_hash):
            challenge.attempts += 1
            if challenge.attempts >= EmailVerification.CODE_ATTEMPTS:
                challenge.used_at = timezone.now()
            challenge.save(update_fields=["attempts", "used_at"])
            return False
        _mark_verified(account, challenge)
        return True


def find_by_link(token: str):
    """The live challenge a link points at, or None."""
    challenge = (
        EmailVerification.objects.select_related("account")
        .filter(token_hash=EmailVerification.hash_link(token or ""), used_at__isnull=True, expires_at__gt=timezone.now())
        .first()
    )
    if challenge is None or challenge.email != challenge.account.email:
        return None
    return challenge


def verify_link(token: str):
    """Confirm through the emailed link. Returns the account, or None."""
    with transaction.atomic():
        challenge = find_by_link(token)
        if challenge is None:
            return None
        challenge = EmailVerification.objects.select_for_update().select_related("account").get(pk=challenge.pk)
        if challenge.used_at is not None:
            return None
        _mark_verified(challenge.account, challenge)
        return challenge.account
