import json
import os
import resource
import subprocess
import sys
import time
from datetime import timedelta

from django.conf import settings
from django.core.management.base import BaseCommand
from django.utils import timezone

from analysis.models import Submission


def limits():
    os.umask(0o077)
    resource.setrlimit(resource.RLIMIT_CPU, (30, 30))
    resource.setrlimit(resource.RLIMIT_AS, (512 * 1024**2, 512 * 1024**2))
    resource.setrlimit(resource.RLIMIT_NOFILE, (64, 64))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))


class Command(BaseCommand):
    help = "Procesa archivos en un subproceso limitado. No ejecuta sus contenidos."

    def add_arguments(self, parser):
        parser.add_argument("--once", action="store_true")

    def handle(self, *args, **options):
        while True:
            # Recover interrupted jobs without reprocessing or giving a false clean verdict.
            stale = Submission.objects.filter(
                status="running", started_at__lt=timezone.now() - timedelta(minutes=5)
            )
            stale.update(
                status="failed",
                verdict="inconclusive",
                finished_at=timezone.now(),
                details={"error": "worker_interrupted"},
            )
            item = Submission.objects.filter(status="queued").order_by("created_at").first()
            if item and Submission.objects.filter(pk=item.pk, status="queued").update(
                status="running", started_at=timezone.now()
            ):
                path = settings.PRIVATE_STORAGE / str(item.id)
                try:
                    process = subprocess.run(
                        [
                            sys.executable,
                            "-m",
                            "analysis.scanner",
                            str(path),
                            item.filename,
                            item.kind,
                        ],
                        cwd=settings.BASE_DIR,
                        capture_output=True,
                        text=True,
                        timeout=90,
                        check=True,
                        preexec_fn=limits,
                        env={
                            name: value
                            for name, value in os.environ.items()
                            if name
                            in {
                                "PATH",
                                "LANG",
                                "HTTPS_PROXY",
                                "HTTP_PROXY",
                                "NO_PROXY",
                                "https_proxy",
                                "http_proxy",
                                "no_proxy",
                                "SSL_CERT_FILE",
                                "SSL_CERT_DIR",
                                "REQUESTS_CA_BUNDLE",
                                "VT_API_KEY",
                                "AI_API_KEY",
                                "AI_MODEL",
                            }
                        },
                    )
                    result = json.loads(process.stdout)
                    if result["verdict"] not in {
                        "malicious",
                        "suspicious",
                        "inconclusive",
                        "no_indicators",
                    }:
                        raise ValueError("Invalid scanner result")
                    Submission.objects.filter(pk=item.pk, status="running").update(
                        status="done",
                        verdict=result["verdict"],
                        details=result["details"],
                        finished_at=timezone.now(),
                    )
                except Exception:
                    Submission.objects.filter(pk=item.pk, status="running").update(
                        status="failed",
                        verdict="inconclusive",
                        finished_at=timezone.now(),
                        details={"error": "scanner_failed_or_timed_out"},
                    )
                finally:
                    path.unlink(missing_ok=True)
            elif not options["once"]:
                time.sleep(2)
            if options["once"]:
                return
