from django.core.management.base import BaseCommand

from entra import graph
from entra.sync import run_all


class Command(BaseCommand):
    help = (
        "Microsoft 365 directory sync tick, run every minute by a systemd timer: renews change "
        "notifications and syncs organizations that were notified or are due (every 15 minutes)."
    )

    def add_arguments(self, parser):
        parser.add_argument("--all", action="store_true", help="Sync every connected organization now.")

    def handle(self, *args, **opts):
        if not graph.configured():
            if opts["verbosity"] > 1 or opts["all"]:
                self.stdout.write("Microsoft 365 integration is not configured; nothing to do.")
            return
        n = run_all(self.stdout, force=opts["all"])
        if n:
            self.stdout.write(f"Synced {n} organization(s).")
