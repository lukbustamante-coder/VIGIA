"""Institutional guidance selected from the module and current technical outcome."""

from .labels import PENDING_STATUSES

SUPPORT_EMAIL = "soporte.sisei@utem.cl"

ASSESSMENTS = {
    "file": {
        "malicious": "Se detectaron indicadores de contenido malicioso en el archivo.",
        "suspicious": "Se encontraron señales sospechosas en el archivo que requieren revisión.",
        "no_indicators": "No se detectaron indicios en las comprobaciones realizadas al archivo. Esto no garantiza que sea seguro.",
        "inconclusive": "La evidencia disponible no permite completar una evaluación concluyente del archivo.",
    },
    "url": {
        "malicious": "Los motores consultados detectaron contenido malicioso asociado al enlace.",
        "suspicious": "Se encontraron detecciones sospechosas asociadas al enlace.",
        "no_indicators": "No se registraron detecciones en el reporte de reputación consultado. Esto no garantiza que el enlace sea seguro.",
        "inconclusive": "No se obtuvo un reporte suficiente para evaluar la reputación del enlace.",
    },
    "eml": {
        "malicious": "Se detectaron indicios maliciosos en el correo o en sus elementos analizados.",
        "suspicious": "Se encontraron señales sospechosas en el correo o en sus elementos analizados.",
        "no_indicators": "No se detectaron indicios en las comprobaciones realizadas al correo. Esto no garantiza que sea legítimo.",
        "inconclusive": "La evidencia disponible no permite completar una evaluación concluyente del correo.",
    },
}

ACTIONS = {
    "url": {
        "malicious": (
            "No abras esta URL ni ingreses datos en el sitio.",
            "Si ya la abriste o necesitas orientación, solicita ayuda a soporte SISEI.",
        ),
        "suspicious": (
            "No abras esta URL hasta que soporte la revise.",
            "Si te la enviaron por correo o mensajería, confirma su legitimidad por otro canal.",
        ),
        "no_indicators": (
            "Verifica el destino antes de abrir la URL.",
            "Si el sitio solicita credenciales, pagos o información personal, confirma la solicitud por otro canal. Ante dudas, consulta a soporte SISEI.",
        ),
        "inconclusive": (
            "Evita abrir esta URL hasta obtener una revisión.",
            "No hay información suficiente para evaluar su reputación. Solicita ayuda a soporte SISEI.",
        ),
    },
    "file": {
        "malicious": (
            "No abras ni ejecutes este archivo.",
            "Reporta el archivo al equipo de Ciberseguridad de UTEM para que revise el caso.",
        ),
        "suspicious": (
            "No abras ni ejecutes este archivo hasta que sea revisado.",
            "Reporta las señales sospechosas al equipo de Ciberseguridad de UTEM.",
        ),
        "no_indicators": (
            "Comprueba que esperabas recibir este archivo y que conoces su origen.",
            "La ausencia de detecciones no garantiza que sea seguro. Ante dudas sobre su origen o contenido, solicita revisión al equipo de Ciberseguridad de UTEM.",
        ),
        "inconclusive": (
            "Mantén el archivo sin abrir hasta que Ciberseguridad lo revise.",
            "No se pudo completar una evaluación concluyente. Reporta el archivo al equipo de Ciberseguridad de UTEM e informa de este resultado.",
        ),
    },
    "eml": {
        "malicious": (
            "No abras enlaces ni adjuntos y no respondas a este correo.",
            "Reporta este mensaje al equipo de Ciberseguridad de UTEM o solicita ayuda a soporte.",
        ),
        "suspicious": (
            "Evita interactuar con este correo: no respondas ni abras sus enlaces o adjuntos.",
            "Reporta el mensaje al equipo de Ciberseguridad de UTEM o a soporte para su revisión.",
        ),
        "no_indicators": (
            "Confirma por otro canal las solicitudes de pagos, contraseñas o datos personales.",
            "La ausencia de indicios no garantiza que el correo sea legítimo. Si el mensaje te genera dudas, repórtalo al equipo de Ciberseguridad de UTEM o a soporte.",
        ),
        "inconclusive": (
            "No respondas ni abras enlaces o adjuntos hasta que el correo sea revisado.",
            "No se pudo completar la evaluación del correo. Solicita revisión al equipo de Ciberseguridad de UTEM o a soporte.",
        ),
    },
}


def guidance_outcome(item):
    if item.status in PENDING_STATUSES:
        return "pending"
    if item.status != "done" and item.verdict not in {"malicious", "suspicious"}:
        return "inconclusive"
    return item.verdict if item.verdict in ASSESSMENTS["file"] else "inconclusive"


def guidance_for(item):
    kind = item.kind if item.kind in ACTIONS else "file"
    outcome = guidance_outcome(item)
    if outcome == "pending":
        noun = {"file": "del archivo", "url": "de la URL", "eml": "del correo"}[kind]
        action = f"Espera a que termine el análisis {noun}."
        detail = "La evaluación sigue en curso; todavía no hay un resultado final."
        email = ""
    else:
        action, detail = ACTIONS[kind][outcome]
        email = SUPPORT_EMAIL if kind in {"url", "eml"} else ""
    contact_label = "Contacta a soporte SISEI:" if email else ""
    text = " ".join(
        part for part in (action, detail, f"{contact_label} {email}." if email else "") if part
    )
    return {
        "action": action,
        "detail": detail,
        "contact_label": contact_label,
        "email": email,
        "text": text,
    }


def assessment_for(item):
    kind = item.kind if item.kind in ASSESSMENTS else "file"
    return ASSESSMENTS[kind].get(guidance_outcome(item), "El análisis sigue en curso.")
