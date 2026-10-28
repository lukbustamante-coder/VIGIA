import os
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
from django.views.decorators.http import require_GET, require_POST, require_safe

from .auth import is_admin
from .forms import FILE_EXTENSIONS, UploadForm, URLAnalysisForm
from .labels import VERDICT_LABELS
from .models import AuditEvent, Submission
from .presentation import email_explanation, result_summary, url_categorization


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


@require_GET
def dashboard(request, module="eml"):
    if not request.user.is_authenticated:
        return render(request, "analysis/welcome.html")
    submissions = (
        Submission.objects.all()
        if is_admin(request)
        else Submission.objects.filter(owner=request.user)
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
                ai_header_consent=bool(form.cleaned_data.get("ai_header_consent")),
                mxtoolbox_consent=bool(form.cleaned_data.get("mxtoolbox_consent")),
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
            AuditEvent.objects.create(actor=request.user, action="upload", submission_id=item.id)
            if item.vt_upload_consent:
                AuditEvent.objects.create(
                    actor=request.user, action="vt_upload_authorized", submission_id=item.id
                )
            if item.ai_header_consent:
                AuditEvent.objects.create(
                    actor=request.user, action="ai_headers_authorized", submission_id=item.id
                )
            if item.mxtoolbox_consent:
                AuditEvent.objects.create(
                    actor=request.user, action="mxtoolbox_authorized", submission_id=item.id
                )
        return redirect("result", pk=item.id)
    except Exception:
        if path:
            path.unlink(missing_ok=True)
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
            url_scan_consent=bool(form.cleaned_data.get("url_scan_consent")),
        )
        AuditEvent.objects.create(
            actor=request.user, action="url_query_authorized", submission_id=item.id
        )
        if item.url_scan_consent:
            AuditEvent.objects.create(
                actor=request.user, action="url_scan_authorized", submission_id=item.id
            )
    return redirect("result", pk=item.id)


@login_required
@require_GET
def result(request, pk):
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
        return JsonResponse(payload)
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
        },
    )


@require_GET
def health(request):
    return JsonResponse({"status": "ok"})
