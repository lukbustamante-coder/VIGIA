"""Operator diagnostics without sample content, filenames, IOC or credentials."""

import json
from pathlib import Path
from uuid import UUID

from django.core.management.base import BaseCommand, CommandError

from analysis.models import Submission


class Command(BaseCommand):
    help = "Muestra las causas del veredicto de los últimos análisis, sin IOC ni secretos."

    def add_arguments(self, parser):
        parser.add_argument("analysis_id", nargs="?", type=UUID)
        parser.add_argument("--limit", type=int, default=5)

    def handle(self, *args, **options):
        if not 1 <= options["limit"] <= 20:
            raise CommandError("El límite debe estar entre 1 y 20.")
        query = Submission.objects.order_by("-created_at")
        if options["analysis_id"]:
            query = query.filter(pk=options["analysis_id"])
        results = []
        for item in query[: options["limit"]]:
            details = item.details
            provider = details.get("providers", {}).get("virustotal", {})
            coverage = details.get("coverage")
            results.append(
                {
                    "id": str(item.id),
                    "module": item.kind,
                    "extension": Path(item.filename).suffix.lower(),
                    "status": item.status,
                    "verdict": item.verdict,
                    "virustotal_status": provider.get("status", "no_record"),
                    "ai_status": details.get("providers", {})
                    .get("ai", {})
                    .get("status", "no_record"),
                    "ai_header_upload_authorized": item.ai_header_consent,
                    "sample_upload_authorized": item.vt_upload_consent,
                    "sample_upload_attempted": provider.get("upload_attempted") is True,
                    "sample_uploaded": provider.get("sample_uploaded"),
                    "coverage": coverage
                    if coverage is not None
                    else {
                        "note": "Reporte anterior: consulta los hallazgos locales y repite el análisis con la versión actual.",
                        "incomplete": details.get("incomplete"),
                    },
                    "local_findings": details.get("findings", []),
                    "processing_error": details.get("error"),
                }
            )
        self.stdout.write(json.dumps(results, ensure_ascii=False, indent=2))
