import uuid

from django.conf import settings
from django.db import models

from .labels import PENDING_STATUSES, STATUS_LABELS, VERDICT_LABELS


class Submission(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    owner = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    kind = models.CharField(
        max_length=8, choices=[("eml", "Correo EML"), ("file", "Archivo"), ("url", "URL")]
    )
    filename = models.CharField(max_length=255)
    target_url = models.URLField(max_length=2048, blank=True)
    url_scan_consent = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    started_at = models.DateTimeField(null=True)
    finished_at = models.DateTimeField(null=True)
    status = models.CharField(max_length=12, default="queued")
    verdict = models.CharField(max_length=24, default="pending")
    details = models.JSONField(default=dict)
    vt_upload_consent = models.BooleanField(default=False)
    ai_header_consent = models.BooleanField(default=False)
    mxtoolbox_consent = models.BooleanField(default=False)
    email_resources_consent = models.BooleanField(default=False)
    vt_next_poll_at = models.DateTimeField(null=True)
    vt_deadline_at = models.DateTimeField(null=True)
    vt_poll_count = models.PositiveSmallIntegerField(default=0)

    @property
    def status_label(self):
        return STATUS_LABELS.get(self.status, "Estado desconocido")

    @property
    def result_badge(self):
        if self.status in PENDING_STATUSES:
            verdict = "pending"
        elif self.status == "done" and self.verdict in VERDICT_LABELS and self.verdict != "pending":
            verdict = self.verdict
        elif self.status == "failed" and self.verdict in {"malicious", "suspicious"}:
            # Preserve findings from a partial scan, without labeling failed scans as clean.
            verdict = self.verdict
        else:
            verdict = "inconclusive"
        return {"label": VERDICT_LABELS[verdict], "tone": verdict}


class AuditEvent(models.Model):
    actor = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True)
    action = models.CharField(max_length=40)
    submission_id = models.UUIDField(null=True)
    created_at = models.DateTimeField(auto_now_add=True)
