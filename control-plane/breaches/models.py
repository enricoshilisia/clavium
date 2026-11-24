from django.db import models

from accounts.models import Account


class EmailBreachStatus(models.Model):
    """Known data breaches that included an account's email address,
    from Have I Been Pwned. Only the email address is ever sent there."""

    account = models.OneToOneField(Account, related_name="email_breaches", on_delete=models.CASCADE)
    # The person asked for their own address to be checked.
    opted_in = models.BooleanField(default=False)
    checked_at = models.DateTimeField(null=True, blank=True)
    # [{"name", "title", "domain", "date", "data": [...]}], newest first
    breaches = models.JSONField(default=list, blank=True)
    last_error = models.CharField(max_length=300, blank=True)

    def names(self):
        return [b["name"] for b in self.breaches]
