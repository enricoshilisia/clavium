import time

from django.conf import settings
from django.core.management.base import BaseCommand

from breaches import hibp, service


class Command(BaseCommand):
    help = "Check monitored email addresses against Have I Been Pwned (run hourly)."

    def handle(self, *args, **opts):
        if not hibp.configured():
            if opts["verbosity"] > 1:
                self.stdout.write("Have I Been Pwned is not configured; nothing to do.")
            return
        pause = 60 / max(1, settings.CLAVIUM_HIBP_RPM) + 0.5
        n = 0
        for account in service.due():
            try:
                service.check(account)
                n += 1
            except hibp.HibpError as e:
                self.stderr.write(f"stopped: {e}")
                break
            time.sleep(pause)
        if n or opts["verbosity"] > 1:
            self.stdout.write(f"Checked {n} email address(es).")
