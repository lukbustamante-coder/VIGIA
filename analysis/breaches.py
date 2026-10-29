"""Account exposure lookup through the documented HIBP v3 API, never password searches."""

import json
from datetime import date
from urllib.parse import quote

import requests

API = "https://haveibeenpwned.com/api/v3/breachedaccount/"
MAX_RESPONSE_BYTES = 1024 * 1024
SOURCES = (
    {
        "name": "Have I Been Pwned",
        "url": "https://haveibeenpwned.com/",
        "description": "Consulta de correos en filtraciones conocidas. Es la fuente de la consulta automática de VIGIA cuando está habilitada.",
        "mode": "Consulta web y API con suscripción",
    },
    {
        "name": "HPI Identity Leak Checker",
        "url": "https://sec.hpi.de/ilc/",
        "description": "Servicio del Hasso Plattner Institute para comprobar exposición de direcciones de correo. Consulta allí sus condiciones y el mecanismo de entrega del resultado.",
        "mode": "Consulta en el sitio del proveedor",
    },
    {
        "name": "F-Secure Identity Theft Checker",
        "url": "https://www.f-secure.com/en/identity-theft-checker",
        "description": "Comprobación de exposición asociada a un correo. El alcance y la información disponible dependen del servicio.",
        "mode": "Consulta en el sitio del proveedor",
    },
    {
        "name": "Malwarebytes Digital Footprint",
        "url": "https://www.malwarebytes.com/digital-footprint",
        "description": "Herramienta para revisar exposición de datos personales vinculados a un correo. Revisa sus condiciones antes de introducir datos.",
        "mode": "Consulta en el sitio del proveedor",
    },
)


def lookup_account(email, key):
    if not key:
        return {"status": "not_configured"}
    response = None
    try:
        response = requests.get(
            API + quote(email, safe=""),
            headers={
                "hibp-api-key": key,
                "user-agent": "VIGIA-Account-Exposure-Check",
                "Accept": "application/json",
            },
            params={"truncateResponse": "false", "includeUnverified": "false"},
            timeout=(5, 15),
            allow_redirects=False,
            stream=True,
        )
        if response.status_code == 404:
            return {"status": "no_records", "breaches": []}
        errors = {401: "authentication_error", 403: "access_denied", 429: "quota_exceeded"}
        if response.status_code != 200:
            return {"status": errors.get(response.status_code, "unavailable")}
        body = bytearray()
        for chunk in response.iter_content(chunk_size=65536):
            body.extend(chunk)
            if len(body) > MAX_RESPONSE_BYTES:
                return {"status": "invalid_response"}
        records = json.loads(body)
        if not isinstance(records, list) or len(records) > 500:
            return {"status": "invalid_response"}
        breaches = []
        for record in records:
            if not isinstance(record, dict):
                return {"status": "invalid_response"}
            title = record.get("Title") or record.get("Name")
            if not isinstance(title, str) or not title.strip():
                return {"status": "invalid_response"}
            stamp = record.get("BreachDate")
            try:
                stamp = date.fromisoformat(stamp).isoformat() if isinstance(stamp, str) else ""
            except ValueError:
                stamp = ""
            classes = record.get("DataClasses", [])
            if not isinstance(classes, list) or any(
                not isinstance(value, str) for value in classes
            ):
                return {"status": "invalid_response"}
            breaches.append(
                {
                    "title": title[:200],
                    "date": stamp,
                    "data_classes": [value[:100] for value in classes[:30]],
                }
            )
        return {"status": "found" if breaches else "no_records", "breaches": breaches}
    except requests.Timeout:
        return {"status": "timeout"}
    except (requests.RequestException, ValueError, TypeError):
        return {"status": "unavailable"}
    finally:
        if response is not None:
            response.close()


DATA_CLASSES = {
    "Email addresses": "Direcciones de correo",
    "Passwords": "Contraseñas",
    "Password hints": "Pistas de contraseñas",
    "Names": "Nombres",
    "Usernames": "Nombres de usuario",
    "Phone numbers": "Números de teléfono",
    "IP addresses": "Direcciones IP",
    "Physical addresses": "Direcciones postales",
    "Dates of birth": "Fechas de nacimiento",
    "Genders": "Género",
    "Geographic locations": "Ubicaciones geográficas",
    "Credit cards": "Tarjetas de crédito",
    "Partial credit card data": "Datos parciales de tarjetas",
    "Security questions and answers": "Preguntas y respuestas de seguridad",
}

MESSAGES = {
    "found": (
        "warning",
        "Se encontraron registros de exposición",
        "Este correo aparece en las filtraciones indicadas por Have I Been Pwned. No demuestra que alguien tenga acceso actualmente a tu cuenta.",
    ),
    "no_records": (
        "neutral",
        "Sin registros en la fuente consultada",
        "Have I Been Pwned no devolvió registros para este correo. Puede haber filtraciones que no estén incluidas; este resultado no garantiza que la cuenta esté protegida.",
    ),
    "quota_exceeded": (
        "neutral",
        "Consulta temporalmente limitada",
        "Se alcanzó un límite de consultas. Inténtalo más tarde.",
    ),
    "timeout": (
        "neutral",
        "El proveedor no respondió a tiempo",
        "No se pudo completar la consulta. Inténtalo más tarde.",
    ),
    "not_configured": (
        "neutral",
        "Consulta automática no disponible",
        "Puedes utilizar las fuentes de consulta manual que aparecen más abajo.",
    ),
}


def present(result):
    tone, title, message = MESSAGES.get(
        result.get("status"),
        (
            "neutral",
            "No se pudo completar la consulta",
            "No hay un resultado disponible. Inténtalo más tarde o utiliza las fuentes de consulta manual.",
        ),
    )
    return {
        "tone": tone,
        "title": title,
        "message": message,
        "found": result.get("status") == "found",
        "breaches": [
            {
                **record,
                "data_classes": [
                    DATA_CLASSES.get(value, value) for value in record["data_classes"]
                ],
            }
            for record in result.get("breaches", [])
        ],
    }
