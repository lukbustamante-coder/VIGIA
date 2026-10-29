"""Bounded, consented VirusTotal queue for extracted email URLs and MIME attachments."""

import hashlib
import os
import re
import shutil
from email import policy
from email.parser import BytesParser
from pathlib import Path

from .url_inspection import lookup_url, normalize_url
from .virustotal import PENDING_STATUSES, fetch_analysis, valid_analysis_id

MAX_ITEMS = 100
MAX_BYTES = 20 * 1024 * 1024
BATCH_SIZE = 2


def resource_directory(sample_path):
    return Path(str(sample_path) + ".resources")


def cleanup(directory):
    if directory is not None:
        shutil.rmtree(directory, ignore_errors=True)


def prepare(data, urls, directory, *, consent=False):
    if not consent or os.getenv("VT_ALLOW_EMAIL_RESOURCES", "false").lower() != "true":
        return {"status": "not_authorized", "items": []}
    items = []
    skipped = max(0, len(urls) - MAX_ITEMS)
    targets = set()
    for value in sorted(urls)[:MAX_ITEMS]:
        try:
            targets.add(normalize_url(value))
        except ValueError:
            skipped += 1
    for target in sorted(targets):
        items.append({"kind": "url", "target": target, "stage": "lookup"})
    message = BytesParser(policy=policy.default).parsebytes(data)
    remaining = MAX_BYTES
    seen = set()
    # Includes unnamed MIME attachments, but not ordinary body parts.
    for index, part in enumerate(message.walk()):
        if index >= MAX_ITEMS:
            skipped += 1
            break
        if part.is_multipart():
            if part.get_filename() or part.get_content_disposition() == "attachment":
                skipped += 1
            continue
        if not (part.get_filename() or part.get_content_disposition() == "attachment"):
            continue
        content = part.get_payload(decode=True) or b""
        if not content or len(content) > remaining:
            skipped += 1
            continue
        remaining -= len(content)
        digest = hashlib.sha256(content).hexdigest()
        if digest in seen:
            continue
        seen.add(digest)
        Path(directory).mkdir(mode=0o700, exist_ok=True)
        path = Path(directory) / digest
        with path.open("xb") as target:
            path.chmod(0o600)
            target.write(content)
        items.append(
            {
                "kind": "file",
                "sha256": digest,
                "filename": str(part.get_filename() or "attachment.bin")[:255],
                "stage": "lookup",
            }
        )
    return {
        "status": "active" if items else "complete",
        "items": items,
        "skipped": skipped,
        "cursor": 0,
    }


def pending(report):
    return any(item.get("stage") in {"lookup", "poll"} for item in report.get("items", []))


def waiting(details):
    provider = details.get("providers", {}).get("virustotal", {})
    return (
        valid_analysis_id(provider.get("analysis_id"))
        and provider.get("status") in PENDING_STATUSES
    ) or pending(details.get("email_resources", {}))


def advance(report, directory):
    """One bounded batch per worker turn. Uploaded bytes never enter stored JSON."""
    from .scanner import Inspector

    items = report.get("items", [])
    if os.getenv("VT_ALLOW_EMAIL_RESOURCES", "false").lower() != "true":
        for item in items:
            if item.get("stage") in {"lookup", "poll"}:
                item.update(stage="done", provider={"status": "policy_disabled"})
        cleanup(directory)
        report["status"] = "incomplete"
        return report
    count = len(items)
    start = report.get("cursor", 0) % count if count else 0
    attempted = 0
    for offset in range(count):
        position = (start + offset) % count
        item = items[position]
        if item.get("stage") not in {"lookup", "poll"}:
            continue
        if attempted >= BATCH_SIZE:
            break
        attempted += 1
        report["cursor"] = (position + 1) % count
        if item["stage"] == "poll":
            provider = {
                **item["provider"],
                **fetch_analysis(item["provider"].get("analysis_id"), os.getenv("VT_API_KEY", "")),
            }
        elif item["kind"] == "url":
            try:
                provider = lookup_url(item["target"], scan_consent=True)
            except ValueError:
                provider = {"status": "invalid_url"}
        else:
            digest = item.get("sha256", "")
            path = (
                Path(directory) / digest
                if directory and re.fullmatch(r"[a-f0-9]{64}", digest)
                else None
            )
            if path is None or not path.is_file():
                provider = {"status": "sample_unavailable"}
            else:
                inspector = Inspector()
                inspector.virus_total(
                    digest, data=path.read_bytes(), filename=item["filename"], upload_consent=True
                )
                provider = inspector.providers["virustotal"]
                if provider.get("status") != "quota_exceeded" or provider.get("upload_attempted"):
                    path.unlink(missing_ok=True)
        item["provider"] = provider
        # Category dictionaries are unrelated to email reputation and can multiply queue size.
        provider.pop("categories", None)
        if (
            valid_analysis_id(provider.get("analysis_id"))
            and provider["status"] in PENDING_STATUSES
        ):
            item["stage"] = "poll"
        elif provider["status"] == "quota_exceeded" and not (
            provider.get("upload_attempted") or provider.get("url_scan_attempted")
        ):
            item["stage"] = "lookup"
        else:
            item["stage"] = "done"
        if provider["status"] in {"quota_exceeded", "authentication_error", "access_denied"}:
            if provider["status"] != "quota_exceeded":
                for remaining in items:
                    if remaining.get("stage") in {"lookup", "poll"}:
                        remaining.update(stage="done", provider={"status": provider["status"]})
                cleanup(directory)
            break
    report["status"] = "active" if pending(report) else "complete"
    return report


def apply(inspector, report):
    if report.get("status") == "not_authorized":
        return
    incomplete = bool(report.get("skipped"))
    for item in report.get("items", []):
        provider = item.get("provider", {})
        if item.get("stage") != "done" or provider.get("status") != "ok":
            incomplete = True
            continue
        stats = provider["stats"]
        inspector.malicious |= stats.get("malicious", 0) >= 2
        inspector.suspicious |= stats.get("malicious", 0) == 1 or stats.get("suspicious", 0) > 0
        inspector.reputation_available = True
    if incomplete:
        inspector.incomplete = True
        inspector.coverage_reason(
            "email_resources",
            "partial_results",
            "No todos los enlaces y adjuntos tienen un resultado completo de VirusTotal.",
        )


def public_summary(report):
    if not report or report.get("status") == "not_authorized":
        return "Los enlaces y adjuntos no se enviaron individualmente a VirusTotal: falta habilitación o autorización."
    parts = []
    for kind, label in (("url", "enlaces"), ("file", "adjuntos distintos")):
        items = [item for item in report.get("items", []) if item.get("kind") == kind]
        if not items:
            continue
        checked = sum(item.get("provider", {}).get("status") == "ok" for item in items)
        flagged = sum(
            item.get("provider", {}).get("status") == "ok"
            and (
                item["provider"]["stats"].get("malicious", 0) > 0
                or item["provider"]["stats"].get("suspicious", 0) > 0
            )
            for item in items
        )
        parts.append(
            f"VirusTotal: {checked} de {len(items)} {label} con resultado; {flagged} con detecciones."
        )
    if pending(report):
        parts.append("Hay consultas pendientes.")
    elif any(item.get("provider", {}).get("status") != "ok" for item in report.get("items", [])):
        parts.append(
            "Algunos elementos quedaron sin resultado por falta de reporte, permisos, cuota o un error de consulta."
        )
    if report.get("skipped"):
        parts.append("Se omitieron elementos por formato no admitido o límites de revisión.")
    if not parts:
        return "No se identificaron enlaces o adjuntos aptos para consultar en VirusTotal."
    return " ".join(parts)
