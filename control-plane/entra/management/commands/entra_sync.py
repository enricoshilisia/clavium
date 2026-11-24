from django.core.management.base import BaseCommand

from entra import graph
from entra.sync import run_all


class Command(BaseCommand):
    help = "Sync every connected organization with its Microsoft 365 groups (run by a systemd timer)."

    def handle(self, *args, **opts):
        if not graph.configured():
            self.stdout.write("Microsoft 365 integration is not configured; nothing to do.")
            return
        n = run_all(self.stdout)
        self.stdout.write(f"Synced {n} organization(s).")
