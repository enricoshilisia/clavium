from django.core.management.base import BaseCommand
from django.db.models import F

from accounts import email_verification
from accounts.models import Account


class Command(BaseCommand):
    help = "Show email verification status, or mark existing accounts verified before turning it on."

    def add_arguments(self, parser):
        parser.add_argument(
            "--mark-existing",
            action="store_true",
            help="Treat every account that exists right now as verified (use once, before switching to 'required').",
        )

    def handle(self, *args, **opts):
        if opts["mark_existing"]:
            n = Account.objects.filter(email_verified_at__isnull=True).update(email_verified_at=F("created_at"))
            self.stdout.write(f"Marked {n} existing account(s) as verified.")
        total = Account.objects.count()
        verified = Account.objects.filter(email_verified_at__isnull=False).count()
        self.stdout.write(f"Mode: {email_verification.mode()}. Verified: {verified} of {total} account(s).")
