"""Invite emails, used by the console and by directory sync."""

from django.conf import settings
from django.core.mail import EmailMultiAlternatives
from django.template.loader import render_to_string


def public_base(request=None) -> str:
    if settings.CLAVIUM_PUBLIC_URL:
        return settings.CLAVIUM_PUBLIC_URL.rstrip("/")
    return request.build_absolute_uri("/").rstrip("/") if request is not None else ""


def send_invite(org, account, raw_token: str, base: str) -> bool:
    """Email an invite link. Returns False when there is no public URL to
    build the link from (the link is still in the console)."""
    if not base:
        return False
    ctx = {"org": org.name, "link": f"{base}/console/invite/{raw_token}/", "name": account.display_name}
    msg = EmailMultiAlternatives(
        subject=f"You have been invited to Clavium by {org.name}",
        body=render_to_string("orgs/email/invite.txt", ctx),
        from_email=settings.DEFAULT_FROM_EMAIL,
        to=[account.email],
    )
    msg.attach_alternative(render_to_string("orgs/email/invite.html", ctx), "text/html")
    msg.send()
    return True
