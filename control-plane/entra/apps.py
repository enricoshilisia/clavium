from django.apps import AppConfig


class EntraConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "entra"
    verbose_name = "Microsoft 365 (Entra ID) directory sync"
