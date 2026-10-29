"""Present evidence and institutional guidance with explicit public/admin boundaries."""

from datetime import UTC, datetime
from pathlib import Path

from .ai_reports import clean_report
from .email_language import (
    concise_content,
    concise_evidence,
    explain_content,
    explain_method,
    explain_routing,
)
from .email_resources import public_summary as public_resource_summary
from .labels import PENDING_STATUSES, STATUS_LABELS
from .mxtoolbox import public_summary as public_dns_summary
from .recommendations import assessment_for, guidance_for
from .url_categories import public_categories


def url_categorization(item):
    if item.kind != "url":
        return None
    if item.status in {"queued", "running", "waiting_vt", "polling_vt"}:
        return {"status": "pending", "labels": []}
    providers = item.details.get("providers", {}) if isinstance(item.details, dict) else {}
    return public_categories(providers.get("virustotal", {}).get("categories"))


def email_explanation(item):
    if item.kind != "eml" or item.status not in {"done", "failed", "waiting_vt", "polling_vt"}:
        return None
    details = item.details if isinstance(item.details, dict) else {}
    headers = details.get("email_headers") or {}
    declared = headers.get("declared_authentication", {})
    methods = []
    for method in ("spf", "dkim", "dmarc"):
        methods.append(explain_method(method, declared.get(method, [])))
    providers = details.get("providers", {})
    ai = providers.get("ai", {})
    report = None
    if ai.get("status") == "ok" and ai.get("version") == 1:
        try:
            report = clean_report(ai.get("user_report"))
        except ValueError:
            pass
    # The recommendation is available even when no AI response could be generated.
    recommendation = guidance_for(item)["text"]
    if report:
        report["recommendation"] = recommendation
    return {
        "methods": methods,
        "report": report,
        "available": report is not None,
        "scope": "headers" if ai.get("data_scope") == "headers" else "technical_findings",
        "routing_explanation": explain_routing(headers),
        "content_explanation": explain_content(details, headers),
        "routing_summary": concise_evidence(headers, methods),
        "content_summary": concise_content(details, headers),
        "resource_summary": public_resource_summary(details.get("email_resources")),
        "recommendation": recommendation,
        "dns_configuration": public_dns_summary(providers.get("mxtoolbox")),
    }


VT_MESSAGES = {
    "not_configured": "VirusTotal no estaba configurado al realizar este análisis.",
    "unknown_hash": "VirusTotal no tiene un reporte para este hash. El archivo no se ha enviado.",
    "unknown_url": "VirusTotal no tiene un reporte de esta URL y no se solicitó un análisis nuevo.",
    "unavailable": "No fue posible obtener el reporte de VirusTotal.",
    "empty_report": "El reporte no contiene resultados de motores.",
    "no_results": "VirusTotal no contiene resultados concluidos de motores.",
    "authentication_error": "VirusTotal rechazó la API key utilizada por el worker.",
    "access_denied": "La cuenta de VirusTotal no tiene permiso para esta consulta.",
    "quota_exceeded": "Se alcanzó la cuota de consultas de VirusTotal.",
    "timeout": "VirusTotal no respondió dentro del tiempo de espera.",
    "invalid_response": "VirusTotal devolvió un reporte sin estadísticas válidas.",
    "queued": "Muestra enviada con autorización. VirusTotal aún está procesando el archivo.",
    "in-progress": "VirusTotal está analizando la muestra autorizada.",
    "analysis_not_found": "VirusTotal no encuentra el análisis solicitado.",
    "analysis_timeout": "VirusTotal no completó el análisis dentro del plazo de espera.",
}
STAT_KEYS = (
    "malicious",
    "suspicious",
    "undetected",
    "harmless",
    "timeout",
    "confirmed-timeout",
    "failure",
    "type-unsupported",
)


def result_summary(item, admin):
    pending = item.status in PENDING_STATUSES
    summary = {
        "pending": pending,
        "status_label": STATUS_LABELS.get(item.status, "Estado desconocido"),
        "tone": "pending" if pending else item.verdict,
        "message": assessment_for(item),
        "guidance": guidance_for(item),
        "symbol": {"malicious": "!", "suspicious": "!", "no_indicators": "✓"}.get(
            item.verdict, "?"
        ),
    }
    if pending:
        subject = {"file": "El archivo", "eml": "El correo", "url": "La URL"}.get(
            item.kind, "El archivo"
        )
        object_name = {"file": "el archivo", "eml": "el correo", "url": "la URL"}.get(
            item.kind, "el archivo"
        )
        summary["symbol"] = "···"
        summary["message"] = (
            f"{subject} espera su turno. El resultado se actualizará automáticamente."
            if item.status == "queued"
            else f"Estamos revisando {object_name}. El resultado se actualizará automáticamente."
        )
        if item.status in {"waiting_vt", "polling_vt"}:
            summary["message"] = (
                f"Estamos esperando el resultado de VirusTotal para {object_name}; puede tardar varios minutos. Esta página se actualizará automáticamente."
            )
    if (
        pending
        and item.kind == "eml"
        and isinstance(item.details, dict)
        and item.details.get("email_resources", {}).get("status") == "active"
    ):
        summary["message"] = (
            "Estamos consultando en VirusTotal los enlaces y adjuntos autorizados. El resultado se actualizará automáticamente; el tiempo depende de la cantidad de elementos y la cuota disponible."
        )
    if not admin:
        return summary

    details = item.details if isinstance(item.details, dict) else {}
    file = details.get("file", {})
    file = file if isinstance(file, dict) else {}
    providers = details.get("providers", {})
    providers = providers if isinstance(providers, dict) else {}
    vt = providers.get("virustotal", {})
    vt = vt if isinstance(vt, dict) else {}
    size = file.get("size_bytes")
    summary.update(
        {
            "filename": item.target_url if item.kind == "url" else item.filename,
            "file_type": "URL"
            if item.kind == "url"
            else Path(item.filename).suffix.lstrip(".").upper()[:12] or "ARCHIVO",
            "file_size": size if type(size) is int and size >= 0 else None,
            "file_hash": file.get("sha256", ""),
            "created_at": item.created_at,
            "finished_at": item.finished_at,
            "has_report": False,
            "sample_uploaded": vt.get("sample_uploaded") is True,
            "url_submitted": vt.get("url_submitted") is True,
            "vt_message": "Consulta pendiente."
            if pending
            else VT_MESSAGES.get(
                vt.get("status"), "Este análisis no contiene un reporte de VirusTotal."
            ),
        }
    )
    stamp = vt.get("last_analysis_date")
    if type(stamp) is int and stamp > 0:
        try:
            summary["vt_date"] = datetime.fromtimestamp(stamp, tz=UTC)
        except (ValueError, OverflowError, OSError):
            pass
    stats = vt.get("stats")
    if pending or vt.get("status") != "ok" or not isinstance(stats, dict):
        return summary
    counts = {name: stats.get(name, 0) for name in STAT_KEYS}
    if any(type(value) is not int or not 0 <= value <= 10000 for value in counts.values()):
        summary["vt_message"] = "El reporte contiene estadísticas no compatibles."
        return summary
    total = sum(counts.values())
    if total == 0:
        summary["vt_message"] = VT_MESSAGES["empty_report"]
        return summary
    unflagged = counts["undetected"] + counts["harmless"]
    summary.update(
        {
            "has_report": True,
            "malicious": counts["malicious"],
            "suspicious": counts["suspicious"],
            "unflagged": unflagged,
            "not_covered": total - unflagged - counts["malicious"] - counts["suspicious"],
            "total": total,
            "score_label": f"{counts['malicious']} de {total} motores reportan contenido malicioso en VirusTotal",
            "ring_percent": max(1, round(100 * counts["malicious"] / total))
            if counts["malicious"]
            else 100,
            "score_tone": "detected"
            if counts["malicious"]
            else "warning"
            if counts["suspicious"]
            else "neutral",
        }
    )
    return summary
