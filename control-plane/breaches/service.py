from datetime import timedelta

from django.conf import settings
from django.core.mail import send_mail
from django.db.models import Q
from django.utils import timezone

from orgs.models import AuditLogEntry, Membership

from . import hibp
from .models import EmailBreachStatus

RECHECK_AFTER = timedelta(days=7)


def monitored_accounts():
    """People who asked to be checked, and members of organizations that
    turned breach checks on."""
    from accounts.models import Account

    org_member_ids = Membership.objects.filter(
        removed_at__isnull=True, organization__policy__check_email_breaches=True
    ).values_list("account_id", flat=True)
    return Account.objects.filter(is_active=True).filter(Q(id__in=org_member_ids) | Q(email_breaches__opted_in=True)).distinct()


def check(account, notify=True) -> EmailBreachStatus:
    status, _ = EmailBreachStatus.objects.get_or_create(account=account)
    try:
        found = hibp.breaches_for(account.email)
    except hibp.HibpError as e:
        status.last_error = str(e)[:300]
        status.save(update_fields=["last_error"])
        raise
    new = [b for b in found if b["name"] not in set(status.names())]
    first_check = status.checked_at is None
    status.breaches, status.checked_at, status.last_error = found, timezone.now(), ""
    status.save(update_fields=["breaches", "checked_at", "last_error"])
    if new:
        AuditLogEntry.record(organization=None, actor=None, action="breach.email_found", obj=status, breaches=[b["name"] for b in new])
        if notify and not first_check:
            _email(account, new)
    return status


def _email(account, new):
    lines = "\n".join(f"- {b['title']} ({b['date']}): {', '.join(b['data'][:5])}" for b in new)
    send_mail(
        subject="Your email address appeared in a data breach",
        message=(
            f"Clavium found {account.email} in {len(new)} newly published data breach{'es' if len(new) != 1 else ''}:\n\n{lines}\n\n"
            "Change the password on those sites, and anywhere you used the same password. "
            "Open Clavium and look at Password health to see which of your saved passwords are affected.\n\n"
            "Clavium never asks for your master password by email."
        ),
        from_email=settings.DEFAULT_FROM_EMAIL,
        recipient_list=[account.email],
        fail_silently=True,
    )


def due(limit=50):
    cutoff = timezone.now() - RECHECK_AFTER
    return [
        a
        for a in monitored_accounts().filter(Q(email_breaches__isnull=True) | Q(email_breaches__checked_at__isnull=True) | Q(email_breaches__checked_at__lt=cutoff))[:limit]
    ]
