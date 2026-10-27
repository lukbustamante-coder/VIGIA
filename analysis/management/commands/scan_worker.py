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

from analysis.models import AuditEvent, Submission
from analysis.virustotal import PENDING_STATUSES, valid_analysis_id


def limits():
    os.umask(0o077)
    resource.setrlimit(resource.RLIMIT_CPU, (30, 30))
    resource.setrlimit(resource.RLIMIT_AS, (512 * 1024**2, 512 * 1024**2))
    resource.setrlimit(resource.RLIMIT_NOFILE, (64, 64))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))


def finish_error(item, error, provider_status=None):
    details = item.details.copy()
    local = details.get("local_assessment", {})
    verdict = (
        "malicious"
        if local.get("malicious")
        else "suspicious"
        if local.get("suspicious")
        else "inconclusive"
    )
    details["error"] = error
    details["incomplete"] = True
    if provider_status:
        details.setdefault("providers", {}).setdefault("virustotal", {})["status"] = provider_status
        coverage = details.setdefault("coverage", {})
        coverage["reputation_available"] = False
        coverage.setdefault("reasons", []).append(
            {
                "source": "virustotal",
                "code": provider_status,
                "message": "El análisis externo no se completó dentro del plazo de espera.",
            }
        )
    Submission.objects.filter(pk=item.pk).update(
        status="failed",
        verdict=verdict,
        details=details,
        finished_at=timezone.now(),
        vt_next_poll_at=None,
    )


class Command(BaseCommand):
    help = (
        "Procesa archivos y consulta análisis externos sin bloquear la cola ni ejecutar muestras."
    )

    def add_arguments(self, parser):
        parser.add_argument("--once", action="store_true")

    def handle(self, *args, **options):
        while True:
            stale = Submission.objects.filter(
                status__in=["running", "polling_vt"],
                started_at__lt=timezone.now() - timedelta(minutes=5),
            )
            for item in stale:
                finish_error(item, "worker_interrupted")
            item = (
                Submission.objects.filter(
                    status="waiting_vt",
                    vt_next_poll_at__lte=timezone.now(),
                )
                .order_by("vt_next_poll_at")
                .first()
            )
            if item:
                self.process(item, polling=True)
            else:
                item = Submission.objects.filter(status="queued").order_by("created_at").first()
                if item:
                    self.process(item, polling=False)
                elif not options["once"]:
                    time.sleep(2)
            if options["once"]:
                return

    def process(self, item, *, polling):
        previous = "waiting_vt" if polling else "queued"
        active = "polling_vt" if polling else "running"
        if not Submission.objects.filter(pk=item.pk, status=previous).update(
            status=active,
            started_at=timezone.now(),
        ):
            return
        if polling and (
            not item.vt_deadline_at
            or item.vt_deadline_at <= timezone.now()
            or item.vt_poll_count >= 60
        ):
            finish_error(item, "external_analysis_timeout", "analysis_timeout")
            return
        path = settings.PRIVATE_STORAGE / str(item.id)
        command = [sys.executable, "-m", "analysis.scanner"]
        if polling:
            command.append("--poll-vt")
        elif item.kind == "url":
            command.append("--url")
        else:
            command.extend([str(path), item.filename, item.kind])
            if item.vt_upload_consent and settings.VT_ALLOW_SAMPLE_UPLOAD:
                command.append("--upload-to-vt")
            if item.ai_header_consent and item.kind == "eml" and settings.AI_ALLOW_HEADER_UPLOAD:
                command.append("--ai-headers")
            if item.mxtoolbox_consent and item.kind == "eml" and settings.MXTOOLBOX_ENABLED:
                command.append("--mxtoolbox")
        scanner_env = {
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
                "AI_PROVIDER",
                "OPENAI_API_KEY",
                "GEMINI_API_KEY",
                "GEMINI_MODEL",
            }
        }
        scanner_env["VT_ALLOW_SAMPLE_UPLOAD"] = (
            "true" if settings.VT_ALLOW_SAMPLE_UPLOAD else "false"
        )
        scanner_env["AI_ALLOW_HEADER_UPLOAD"] = (
            "true" if settings.AI_ALLOW_HEADER_UPLOAD else "false"
        )
        mxtoolbox_enabled = (
            not polling
            and item.kind == "eml"
            and item.mxtoolbox_consent
            and settings.MXTOOLBOX_ENABLED
        )
        scanner_env["MXTOOLBOX_ENABLED"] = "true" if mxtoolbox_enabled else "false"
        if mxtoolbox_enabled:
            scanner_env["MXTOOLBOX_API_KEY"] = settings.MXTOOLBOX_API_KEY
        scanner_env["VT_ALLOW_URL_SUBMISSION"] = (
            "true" if settings.VT_ALLOW_URL_SUBMISSION else "false"
        )
        scanner_input = (
            json.dumps(item.details)
            if polling
            else (
                json.dumps({"url": item.target_url, "scan_consent": item.url_scan_consent})
                if item.kind == "url"
                else None
            )
        )
        try:
            process = subprocess.run(
                command,
                input=scanner_input,
                cwd=settings.BASE_DIR,
                capture_output=True,
                text=True,
                timeout=150 if mxtoolbox_enabled and not polling else 90,
                check=True,
                preexec_fn=limits,
                env=scanner_env,
            )
            result = json.loads(process.stdout)
            if result["verdict"] not in {
                "malicious",
                "suspicious",
                "inconclusive",
                "no_indicators",
            }:
                raise ValueError("Invalid scanner result")
            provider = result["details"].get("providers", {}).get("virustotal", {})
            if not polling and any(
                check.get("request_attempted")
                for check in result["details"]
                .get("providers", {})
                .get("mxtoolbox", {})
                .get("checks", [])
            ):
                AuditEvent.objects.create(
                    actor=item.owner, action="mxtoolbox_attempt", submission_id=item.id
                )
            if not polling and item.kind == "url":
                if provider.get("query_attempted"):
                    AuditEvent.objects.create(
                        actor=item.owner, action="url_query_attempt", submission_id=item.id
                    )
                if provider.get("url_scan_attempted"):
                    AuditEvent.objects.create(
                        actor=item.owner, action="url_scan_attempt", submission_id=item.id
                    )
            if not polling and result["details"].get("providers", {}).get("ai", {}).get(
                "header_upload_attempted"
            ):
                AuditEvent.objects.create(
                    actor=item.owner, action="ai_headers_attempt", submission_id=item.id
                )
            if not polling and provider.get("upload_attempted"):
                AuditEvent.objects.create(
                    actor=item.owner, action="vt_upload_attempt", submission_id=item.id
                )
            if not polling and provider.get("sample_uploaded"):
                AuditEvent.objects.create(
                    actor=item.owner, action="vt_sample_uploaded", submission_id=item.id
                )
            waiting = (
                valid_analysis_id(provider.get("analysis_id"))
                and provider.get("status") in PENDING_STATUSES
            )
            if waiting:
                delay = 60 if provider["status"] == "quota_exceeded" else 30
                Submission.objects.filter(pk=item.pk, status=active).update(
                    status="waiting_vt",
                    verdict="pending",
                    details=result["details"],
                    vt_next_poll_at=timezone.now() + timedelta(seconds=delay),
                    vt_deadline_at=item.vt_deadline_at or timezone.now() + timedelta(minutes=30),
                    vt_poll_count=item.vt_poll_count + int(polling),
                )
            else:
                Submission.objects.filter(pk=item.pk, status=active).update(
                    status="done",
                    verdict=result["verdict"],
                    details=result["details"],
                    finished_at=timezone.now(),
                    vt_next_poll_at=None,
                    vt_poll_count=item.vt_poll_count + int(polling),
                )
                if polling and provider.get("status") == "ok":
                    AuditEvent.objects.create(
                        actor=item.owner, action="vt_analysis_completed", submission_id=item.id
                    )
        except Exception:
            finish_error(item, "scanner_failed_or_timed_out")
        finally:
            if not polling and item.kind != "url":
                path.unlink(missing_ok=True)
