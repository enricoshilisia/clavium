from datetime import timedelta

from django.core.management.base import BaseCommand
from django.utils import timezone

from shares.models import Share


class Command(BaseCommand):
    help = "Wipe the ciphertext of expired share links and delete old records."

    def handle(self, *args, **opts):
        now = timezone.now()
        wiped = Share.objects.filter(expires_at__lte=now).exclude(ciphertext="").update(ciphertext="", nonce="", wiped_at=now)
        deleted, _ = Share.objects.filter(expires_at__lte=now - timedelta(days=30)).delete()
        if wiped or deleted or opts["verbosity"] > 1:
            self.stdout.write(f"Wiped {wiped} expired link(s), deleted {deleted} old record(s).")
