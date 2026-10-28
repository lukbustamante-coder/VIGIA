"""Spanish UI labels; stored status/verdict codes remain stable for workers and polling."""

STATUS_LABELS = {
    "queued": "En cola",
    "running": "Analizando",
    "waiting_vt": "Esperando a VirusTotal",
    "polling_vt": "Consultando VirusTotal",
    "done": "Listo",
    "failed": "No completado",
}

VERDICT_LABELS = {
    "pending": "Pendiente",
    "malicious": "Malicioso",
    "suspicious": "Sospechoso",
    "no_indicators": "Sin indicios detectados",
    "inconclusive": "No concluyente",
}

PENDING_STATUSES = {"queued", "running", "waiting_vt", "polling_vt"}
