"""Owner-triggered support reports, private samples and a durable SMTP outbox."""

import hashlib
import json
import os
import smtplib
from datetime import timedelta
from pathlib import Path

from django import forms
from django.conf import settings
from django.core.mail import EmailMessage
from django.db import transaction
from django.utils import timezone

from .forms import UploadForm
from .mail_backend import PartialDelivery
from .models import AuditEvent, IncidentReport, Submission

RECIPIENTS = ("soporte.sisei@utem.cl", "sisei-infraestructura@utem.cl")


def sample_path(item):
    return settings.PRIVATE_STORAGE / "report-samples" / str(item.pk)


def save_sample(item, content):
    path = sample_path(item)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(path.parent, 0o700)
    with path.open("xb") as stream:
        os.chmod(path, 0o600)
        stream.write(content)


def eligible(item):
    return item.status in {"done", "failed"} and item.result_badge["tone"] in {
        "malicious",
        "suspicious",
        "inconclusive",
    }


def mail_ready():
    return bool(
        settings.REPORT_MAIL_ENABLED and settings.EMAIL_HOST and settings.DEFAULT_FROM_EMAIL
    )


class ReportForm(forms.Form):
    email = forms.EmailField(label="Correo para contactarte", max_length=254)
    sample = forms.FileField(label="Vuelve a seleccionar el archivo original", required=False)

    def __init__(self, *args, item, contact_email="", **kwargs):
        super().__init__(*args, **kwargs)
        self.item = item
        self.fields["email"].initial = contact_email
        if contact_email:
            self.fields["email"].disabled = True
        if item.kind == "url" or sample_path(item).is_file():
            self.fields.pop("sample")
        else:
            self.fields["sample"].required = True
            self.fields["sample"].help_text = (
                "El original de este análisis ya no está disponible. Selecciónalo otra vez "
                "para adjuntarlo al reporte. Se comprobará que sea el mismo archivo."
            )

    def clean_sample(self):
        sample = self.cleaned_data.get("sample")
        if not sample:
            return sample
        validation = UploadForm({"kind": self.item.kind}, {"file": sample})
        if not validation.is_valid():
            raise forms.ValidationError(
                "Selecciona un archivo válido del mismo tipo, de hasta 20 MB."
            )
        expected = self.item.details.get("file", {}).get("sha256")
        digest = hashlib.sha256()
        for chunk in sample.chunks():
            digest.update(chunk)
        sample.seek(0)
        if not expected:
            raise forms.ValidationError(
                "Este reporte no conserva el hash original. Vuelve a analizar el archivo para reportarlo."
            )
        if digest.hexdigest() != expected:
            raise forms.ValidationError("El archivo no coincide con el original de este análisis.")
        return sample


def report_context(item, contact_email="", form=None):
    report = getattr(item, "incident_report", None)
    return {
        "eligible": eligible(item),
        "record": report,
        "ready": mail_ready(),
        "pending": bool(report and report.status in {"queued", "sending"}),
        "form": form if form is not None else ReportForm(item=item, contact_email=contact_email),
    }


def queue_report(item, reporter, form):
    with transaction.atomic():
        # Serialize duplicate clicks for this analysis before creating its one-to-one outbox row.
        locked = Submission.objects.select_for_update().get(pk=item.pk)
        existing = IncidentReport.objects.filter(submission=locked).first()
        if existing and existing.status != "failed":
            return existing
        sample = form.cleaned_data.get("sample")
        if sample and not sample_path(locked).exists():
            save_sample(locked, sample.read(settings.MAX_UPLOAD_BYTES + 1))
        if locked.kind != "url" and not sample_path(locked).is_file():
            raise ValueError("missing_sample")
        if existing:
            existing.email = form.cleaned_data["email"]
            existing.status = "queued"
            existing.started_at = None
            existing.save(update_fields=["email", "status", "started_at"])
            report = existing
        else:
            report = IncidentReport.objects.create(
                submission=locked, reporter=reporter, email=form.cleaned_data["email"]
            )
        AuditEvent.objects.create(
            actor=reporter, action="support_report_requested", submission_id=item.pk
        )
        return report


def build_message(report):
    item = report.submission
    module = {"eml": "Correo EML", "file": "Archivo", "url": "URL"}[item.kind]
    body = (
        "REPORTE DE SEGURIDAD VIGIA\n"
        "Tratar la muestra y sus enlaces como potencialmente maliciosos. Revisar en un entorno aislado.\n\n"
        f"Identificador del análisis: {item.pk}\n"
        f"Persona que reporta: {report.reporter.get_full_name() or 'Nombre no disponible'}\n"
        f"Correo de contacto: {report.email}\n"
        "El correo de contacto puede haber sido indicado por la persona si el SSO no lo proporcionó.\n"
        f"Módulo: {module}\n"
        f"Resultado: {item.result_badge['label']}\n"
        f"Estado del análisis: {item.status}\n"
        f"Fecha de carga (UTC): {item.created_at.isoformat()}\n"
        f"Fecha del reporte (UTC): {report.created_at.isoformat()}\n"
        f"Nombre original: {item.filename}\n"
        f"URL reportada: {item.target_url if item.kind == 'url' else 'No aplica'}\n\n"
        "Se adjunta la evidencia técnica en JSON. Para archivos y correos se adjunta también "
        "la muestra original sin ejecutarla. El EML conserva el mensaje y sus adjuntos incluidos.\n"
    )
    message = EmailMessage(
        subject=f"[VIGIA] Reporte de {module} · {item.result_badge['label']} · {item.pk}",
        body=body,
        from_email=settings.DEFAULT_FROM_EMAIL,
        to=list(RECIPIENTS),
        reply_to=[report.email],
        headers={"Message-ID": f"<vigia-report-{item.pk}@utem.cl>"},
    )
    evidence = json.dumps(item.details, ensure_ascii=False, indent=2)
    message.attach(f"evidencia-{item.pk}.json", evidence, "application/json")
    if item.kind != "url":
        path = sample_path(item)
        with path.open("rb") as stream:
            data = stream.read(settings.MAX_UPLOAD_BYTES + 1)
        if not data or len(data) > settings.MAX_UPLOAD_BYTES:
            raise ValueError("invalid_sample_size")
        expected = item.details.get("file", {}).get("sha256")
        if expected and hashlib.sha256(data).hexdigest() != expected:
            raise ValueError("sample_mismatch")
        suffix = ".eml" if item.kind == "eml" else Path(item.filename).suffix
        if not suffix[1:].isalnum() or len(suffix) > 12:
            suffix = ".bin"
        message.attach(f"muestra-{item.pk}{suffix}", data, "application/octet-stream")
    return message


def process_next_report():
    # Never automatically retry an interrupted SMTP DATA exchange: acceptance is ambiguous.
    IncidentReport.objects.filter(
        status="sending", started_at__lt=timezone.now() - timedelta(minutes=5)
    ).update(status="uncertain")
    if not mail_ready():
        return False
    report = (
        IncidentReport.objects.filter(status="queued")
        .select_related("submission", "reporter")
        .order_by("created_at")
        .first()
    )
    if not report:
        return False
    if not IncidentReport.objects.filter(pk=report.pk, status="queued").update(
        status="sending", started_at=timezone.now(), attempts=report.attempts + 1
    ):
        return False
    state = "failed"
    sending = False
    try:
        message = build_message(report)
        sending = True
        accepted = message.send(fail_silently=False)
        if accepted == 1:
            state = "sent"
    except (smtplib.SMTPServerDisconnected, PartialDelivery):
        state = "uncertain"
    except smtplib.SMTPException:
        state = "failed"
    except OSError:
        state = "uncertain" if sending else "failed"
    except Exception:
        # Exceptions can contain passwords, recipient data and SMTP server responses.
        state = "failed"
    IncidentReport.objects.filter(pk=report.pk, status="sending").update(
        status=state, sent_at=timezone.now() if state == "sent" else None
    )
    AuditEvent.objects.create(
        actor=report.reporter, action=f"support_report_{state}", submission_id=report.submission_id
    )
    return True
