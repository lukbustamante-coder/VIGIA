import os
from datetime import timedelta
from pathlib import Path

from django.conf import settings
from django.contrib.auth.decorators import login_required
from django.db import transaction
from django.http import Http404, JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.utils import timezone
from django.views.decorators.http import require_GET, require_POST

from .auth import is_admin
from .forms import UploadForm
from .models import AuditEvent, Submission

LABELS = {
    "pending": "Pendiente",
    "malicious": "Malicioso",
    "suspicious": "Sospechoso",
    "no_indicators": "Sin indicios detectados",
    "inconclusive": "No concluyente",
}


@require_GET
def dashboard(request):
    if not request.user.is_authenticated:
        return render(request, "analysis/welcome.html")
    submissions = (
        Submission.objects.all()
        if is_admin(request)
        else Submission.objects.filter(owner=request.user)
    )
    return render(
        request,
        "analysis/dashboard.html",
        {
            "form": UploadForm(),
            "submissions": submissions.order_by("-created_at")[:50],
            "admin": is_admin(request),
        },
    )


@login_required
@require_POST
def upload(request):
    form = UploadForm(request.POST, request.FILES)
    if not form.is_valid():
        return render(request, "analysis/upload_error.html", {"form": form}, status=400)
    settings.PRIVATE_STORAGE.mkdir(parents=True, exist_ok=True, mode=0o700)
    path = None
    try:
        with transaction.atomic():
            # Per-user lock serializes quota checks on PostgreSQL.
            from django.contrib.auth import get_user_model

            get_user_model().objects.select_for_update().get(pk=request.user.pk)
            recent = Submission.objects.filter(
                owner=request.user, created_at__gte=timezone.now() - timedelta(hours=1)
            ).count()
            pending = Submission.objects.filter(status__in=["queued", "running"]).count()
            if recent >= 20 or pending >= 200:
                return JsonResponse({"error": "Límite temporal de análisis alcanzado."}, status=429)
            file = form.cleaned_data["file"]
            item = Submission.objects.create(
                owner=request.user,
                kind=form.cleaned_data["kind"],
                filename=Path(file.name).name[:255],
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
        return redirect("result", pk=item.id)
    except Exception:
        if path:
            path.unlink(missing_ok=True)
        return JsonResponse({"error": "No se pudo guardar el archivo."}, status=503)


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
        "label": LABELS.get(item.verdict, "No concluyente"),
    }
    if admin:
        payload["details"] = item.details
        AuditEvent.objects.create(actor=request.user, action="view_ioc", submission_id=item.id)
    if request.GET.get("format") == "json":
        return JsonResponse(payload)
    return render(request, "analysis/result.html", {"result": payload, "admin": admin})


@require_GET
def health(request):
    return JsonResponse({"status": "ok"})
