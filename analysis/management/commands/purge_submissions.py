from datetime import timedelta
from uuid import UUID

from django.conf import settings
from django.core.management.base import BaseCommand
from django.utils import timezone

from analysis.email_resources import cleanup
from analysis.models import AuditEvent, Submission


class Command(BaseCommand):
    help = "Elimina resultados de más de 30 días, auditoría de más de 90 y muestras huérfanas."

    def handle(self, *args, **options):
        now = timezone.now()
        Submission.objects.filter(created_at__lt=now - timedelta(days=30)).exclude(
            status="running"
        ).delete()
        AuditEvent.objects.filter(created_at__lt=now - timedelta(days=90)).delete()
        if settings.PRIVATE_STORAGE.exists():
            for path in settings.PRIVATE_STORAGE.iterdir():
                if path.is_dir() and path.name.endswith(".resources"):
                    try:
                        parent = UUID(path.name.removesuffix(".resources"))
                    except ValueError:
                        continue
                    if not Submission.objects.filter(
                        pk=parent, status__in=["queued", "running", "waiting_vt", "polling_vt"]
                    ).exists():
                        cleanup(path)
                    continue
                if (
                    path.is_file()
                    and path.stat().st_mtime < (now - timedelta(minutes=10)).timestamp()
                ):
                    try:
                        UUID(path.name)
                    except ValueError:
                        continue
                    if not Submission.objects.filter(
                        pk=path.name, status__in=["queued", "running"]
                    ).exists():
                        path.unlink(missing_ok=True)
