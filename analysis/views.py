import os
import shutil
from datetime import timedelta
from pathlib import Path
from urllib.parse import urlsplit

from django import forms
from django.conf import settings
from django.contrib.auth.decorators import login_required
from django.db import transaction
from django.http import Http404, JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.templatetags.static import static
from django.utils import timezone
from django.views.decorators.http import (
    require_GET,
    require_http_methods,
    require_POST,
    require_safe,
)

from .auth import is_admin
from .breaches import PROVIDERS, lookup_account, lookup_xposedornot, source_checks
from .breaches import present as present_breach_result
from .forms import FILE_EXTENSIONS, BreachLookupForm, UploadForm, URLAnalysisForm
from .labels import VERDICT_LABELS
from .models import AuditEvent, Submission
from .presentation import email_explanation, result_summary, url_categorization
from .reporting import ReportForm, eligible, mail_ready, queue_report, report_context, sample_path


@require_safe
def favicon(request):
    return redirect(static("analysis/favicon.svg"))


def quota_exceeded(user):
    # Caller holds a transaction; serialize checks per user on PostgreSQL.
    from django.contrib.auth import get_user_model

    get_user_model().objects.select_for_update().get(pk=user.pk)
    recent = Submission.objects.filter(
        owner=user, created_at__gte=timezone.now() - timedelta(hours=1)
    ).count()
    pending = Submission.objects.filter(
        status__in=["queued", "running", "waiting_vt", "polling_vt"]
    ).count()
    return recent >= 20 or pending >= 200


@login_required
@require_http_methods(["GET", "POST"])
def breach_lookup(request):
    provider = settings.BREACH_PROVIDER
    source = PROVIDERS.get(provider)
    enabled = provider == "xposedornot" or (
        provider == "hibp" and settings.HIBP_ENABLED and bool(settings.HIBP_API_KEY)
    )
    form = BreachLookupForm(
        request.POST if request.method == "POST" else None,
        provider_name=source["name"] if source else "el proveedor configurado",
    )
    result = None
    raw_result = None
    status = 200
    if request.method == "POST":
        if not form.is_valid():
            status = 400
        elif not enabled:
            raw_result = {"status": "not_configured"}
            result = present_breach_result(raw_result, provider=provider)
        else:
            from django.contrib.auth import get_user_model

            with transaction.atomic():
                # Serialize quota reservations globally on PostgreSQL; never hold during HTTP.
                get_user_model().objects.select_for_update().order_by("pk").first()
                action = "breach_lookup_xon" if provider == "xposedornot" else "breach_lookup"
                now = timezone.now()
                events = AuditEvent.objects.filter(action=action)
                recent = events.filter(created_at__gte=now - timedelta(hours=1))
                limited = (
                    recent.count() >= (25 if provider == "xposedornot" else 200)
                    or recent.filter(actor=request.user).count() >= 20
                )
                if provider == "xposedornot":
                    limited |= (
                        events.filter(created_at__gte=now - timedelta(hours=24)).count() >= 100
                        or events.filter(created_at__gte=now - timedelta(seconds=1)).exists()
                    )
                if not limited:
                    # Do not retain the queried address, provider response or breach names.
                    AuditEvent.objects.create(actor=request.user, action=action)
            if limited:
                raw_result = {"status": "quota_exceeded"}
                result = present_breach_result(raw_result, provider=provider)
                status = 429
            else:
                raw_result = (
                    lookup_xposedornot(form.cleaned_data["email"])
                    if provider == "xposedornot"
                    else lookup_account(form.cleaned_data["email"], settings.HIBP_API_KEY)
                )
                result = present_breach_result(raw_result, provider=provider)
    return render(
        request,
        "analysis/breach_lookup.html",
        {
            "module": "breach",
            "admin": is_admin(request),
            "form": form,
            "lookup_enabled": enabled,
            "lookup_source": source,
            "is_free_lookup": provider == "xposedornot",
            "lookup_result": result,
            "source_checks": source_checks(provider, raw_result, enabled=enabled),
        },
        status=status,
    )


@require_GET
def dashboard(request, module="eml"):
    if not request.user.is_authenticated:
        return render(request, "analysis/welcome.html")
    submissions = (
        Submission.objects.select_related("incident_report").all()
        if is_admin(request)
        else Submission.objects.select_related("incident_report").filter(owner=request.user)
    )
    if module == "url":
        return render(
            request,
            "analysis/url_dashboard.html",
            {
                "form": URLAnalysisForm(),
                "module": "url",
                "admin": is_admin(request),
                "submissions": submissions.filter(kind="url").order_by("-created_at")[:50],
            },
        )
    form = UploadForm(initial={"kind": module})
    form.fields["kind"].widget = forms.HiddenInput()
    form.fields["file"].label = "Correo EML" if module == "eml" else "Archivo"
    form.fields["file"].widget.attrs["accept"] = (
        ".eml" if module == "eml" else ",".join(f".{ext}" for ext in sorted(FILE_EXTENSIONS))
    )
    return render(
        request,
        "analysis/dashboard.html",
        {
            "form": form,
            "module": module,
            "submissions": submissions.filter(kind=module).order_by("-created_at")[:50],
            "admin": is_admin(request),
        },
    )


@login_required
@require_POST
def upload(request):
    form = UploadForm(request.POST, request.FILES)
    if not form.is_valid():
        module = "file" if request.POST.get("kind") == "file" else "eml"
        return render(
            request,
            "analysis/upload_error.html",
            {"form": form, "module": module, "admin": is_admin(request)},
            status=400,
        )
    settings.PRIVATE_STORAGE.mkdir(parents=True, exist_ok=True, mode=0o700)
    path = None
    try:
        with transaction.atomic():
            if quota_exceeded(request.user):
                return JsonResponse({"error": "Límite temporal de análisis alcanzado."}, status=429)
            file = form.cleaned_data["file"]
            item = Submission.objects.create(
                owner=request.user,
                kind=form.cleaned_data["kind"],
                filename=Path(file.name).name[:255],
                vt_upload_consent=bool(form.cleaned_data.get("vt_upload_consent")),
                # Institutional policy authorizes selected headers; no per-user checkbox.
                ai_header_consent=bool(
                    settings.AI_ALLOW_HEADER_UPLOAD and form.cleaned_data["kind"] == "eml"
                ),
                mxtoolbox_consent=bool(form.cleaned_data.get("mxtoolbox_consent")),
                email_resources_consent=bool(form.cleaned_data.get("email_resources_consent")),
            )
            path = settings.PRIVATE_STORAGE / str(item.id)
            with open(path, "xb") as target:
                os.chmod(path, 0o600)
                total = 0
                for chunk in file.chunks():
                    total += len(chunk)
                    if total > settings.MAX_UPLOAD_BYTES:
                        raise ValueError("Carga demasiado grande")
                    target.write(chunk)
            retained = sample_path(item)
            retained.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            os.chmod(retained.parent, 0o700)
            with path.open("rb") as source, retained.open("xb") as destination:
                os.chmod(retained, 0o600)
                shutil.copyfileobj(source, destination)
            AuditEvent.objects.create(actor=request.user, action="upload", submission_id=item.id)
            if item.vt_upload_consent:
                AuditEvent.objects.create(
                    actor=request.user, action="vt_upload_authorized", submission_id=item.id
                )
            if item.ai_header_consent:
                AuditEvent.objects.create(
                    actor=request.user, action="ai_headers_policy_applied", submission_id=item.id
                )
            if item.mxtoolbox_consent:
                AuditEvent.objects.create(
                    actor=request.user, action="mxtoolbox_authorized", submission_id=item.id
                )
            if item.email_resources_consent:
                AuditEvent.objects.create(
                    actor=request.user, action="email_resources_authorized", submission_id=item.id
                )
        return redirect("result", pk=item.id)
    except Exception:
        if path:
            path.unlink(missing_ok=True)
            sample_path(item).unlink(missing_ok=True)
        return JsonResponse({"error": "No se pudo guardar el archivo."}, status=503)


@login_required
@require_POST
def submit_url(request):
    form = URLAnalysisForm(request.POST)
    if not form.is_valid():
        submissions = (
            Submission.objects.all()
            if is_admin(request)
            else Submission.objects.filter(owner=request.user)
        )
        return render(
            request,
            "analysis/url_dashboard.html",
            {
                "form": form,
                "module": "url",
                "admin": is_admin(request),
                "submissions": submissions.filter(kind="url").order_by("-created_at")[:50],
            },
            status=400,
        )
    with transaction.atomic():
        if quota_exceeded(request.user):
            return JsonResponse({"error": "Límite temporal de análisis alcanzado."}, status=429)
        target = form.cleaned_data["url"]
        item = Submission.objects.create(
            owner=request.user,
            kind="url",
            target_url=target,
            filename=f"URL · {urlsplit(target).hostname}"[:255],
            url_scan_consent=bool(settings.VT_ALLOW_URL_SUBMISSION),
        )
        AuditEvent.objects.create(
            actor=request.user, action="url_query_requested", submission_id=item.id
        )
        if item.url_scan_consent:
            AuditEvent.objects.create(
                actor=request.user, action="url_scan_policy_applied", submission_id=item.id
            )
    return redirect("result", pk=item.id)


@login_required
@require_GET
def result(request, pk):
    return _result_response(request, pk)


def _result_response(request, pk, report_form=None, report_error="", response_status=200):
    item = get_object_or_404(Submission, pk=pk)
    admin = is_admin(request)
    if not admin and item.owner_id != request.user.pk:
        raise Http404
    # Explicitly project user-visible fields. Details never enter the user context or API.
    payload = {
        "id": str(item.id),
        "status": item.status,
        "verdict": item.verdict,
        "label": VERDICT_LABELS.get(item.verdict, "No concluyente"),
    }
    incident = getattr(item, "incident_report", None)
    if incident:
        payload["report"] = {"status": incident.status}
    explanation = email_explanation(item)
    categorization = url_categorization(item)
    if categorization is not None:
        payload["url_category"] = categorization
    if explanation is not None:
        payload["email_analysis"] = explanation
    if admin:
        payload["details"] = item.details
        AuditEvent.objects.create(actor=request.user, action="view_ioc", submission_id=item.id)
    if request.GET.get("format") == "json":
        return JsonResponse(payload, status=response_status)
    return render(
        request,
        "analysis/result.html",
        {
            "result": payload,
            "admin": admin,
            "summary": result_summary(item, admin),
            "module": item.kind,
            "email_analysis": explanation,
            "url_category": categorization,
            "reporting": report_context(
                item, request.session.get("oidc_contact_email", ""), report_form
            )
            if item.owner_id == request.user.pk
            else None,
            "report_error": report_error,
        },
        status=response_status,
    )


@login_required
@require_POST
def report_submission(request, pk):
    item = get_object_or_404(Submission, pk=pk, owner=request.user)
    if not eligible(item):
        return _result_response(
            request,
            pk,
            report_error="Este resultado todavía no está disponible para reportar.",
            response_status=400,
        )
    existing = getattr(item, "incident_report", None)
    if existing and existing.status != "failed":
        return redirect("result", pk=pk)
    if existing and existing.attempts >= 3:
        return _result_response(
            request,
            pk,
            report_error="No pudimos enviar el reporte después de varios intentos. Contacta directamente a soporte.sisei@utem.cl.",
            response_status=429,
        )
    if not mail_ready():
        return _result_response(
            request,
            pk,
            report_error="El envío de reportes aún no está disponible. Puedes contactar directamente a soporte.sisei@utem.cl.",
            response_status=503,
        )
    form = ReportForm(
        request.POST,
        request.FILES,
        item=item,
        contact_email=request.session.get("oidc_contact_email", ""),
    )
    if not form.is_valid():
        return _result_response(request, pk, report_form=form, response_status=400)
    try:
        queue_report(item, request.user, form)
    except (OSError, ValueError):
        return _result_response(
            request,
            pk,
            report_form=form,
            report_error="No pudimos preparar el archivo para el reporte. Vuelve a intentarlo.",
            response_status=503,
        )
    return redirect("result", pk=pk)


@require_GET
def health(request):
    return JsonResponse({"status": "ok"})
