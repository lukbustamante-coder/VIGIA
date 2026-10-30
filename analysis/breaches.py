"""Account exposure through documented APIs; no password queries or automatic failover."""

import json
from datetime import date
from urllib.parse import quote

import requests

API = "https://haveibeenpwned.com/api/v3/breachedaccount/"
XON_API = "https://api.xposedornot.com/v1/check-email/"
PROVIDERS = {
    "xposedornot": {"name": "XposedOrNot", "url": "https://xposedornot.com/"},
    "hibp": {"name": "Have I Been Pwned", "url": "https://haveibeenpwned.com/"},
}
MAX_RESPONSE_BYTES = 1024 * 1024
SOURCES = (
    {
        "id": "xposedornot",
        **PROVIDERS["xposedornot"],
        "description": "Consulta gratuita de correos en filtraciones conocidas. Su API básica funciona sin clave y tiene límites de uso.",
        "mode": "Consulta web y API básica gratuitas",
    },
    {
        "id": "ciberlupa",
        "name": "Ciberlupa · Agencia Nacional de Ciberseguridad (ANCI, CHILE)",
        "url": "https://ciberlupa.anci.gob.cl/verificar/?type=rut",
        "description": "Verificación externa por RUT en Ciberlupa de ANCI. Esta revisión es independiente de la consulta de correo de VIGIA.",
        "mode": "Verificación por RUT en el sitio de ANCI",
    },
    {
        "id": "hibp",
        "name": "Have I Been Pwned",
        "url": "https://haveibeenpwned.com/",
        "description": "Puedes consultar un correo gratuitamente desde su página web. Su API de búsqueda de cuentas requiere una suscripción independiente.",
        "mode": "Consulta web gratuita; API de pago",
    },
    {
        "id": "hpi",
        "name": "HPI Identity Leak Checker",
        "url": "https://sec.hpi.de/ilc/",
        "description": "Servicio del Hasso Plattner Institute para comprobar exposición de direcciones de correo. Consulta allí sus condiciones y el mecanismo de entrega del resultado.",
        "mode": "Consulta en el sitio del proveedor",
    },
    {
        "id": "fsecure",
        "name": "F-Secure Identity Theft Checker",
        "url": "https://www.f-secure.com/en/identity-theft-checker",
        "description": "Comprobación de exposición asociada a un correo. El alcance y la información disponible dependen del servicio.",
        "mode": "Consulta en el sitio del proveedor",
    },
    {
        "id": "malwarebytes",
        "name": "Malwarebytes Digital Footprint",
        "url": "https://www.malwarebytes.com/digital-footprint",
        "description": "Herramienta para revisar exposición de datos personales vinculados a un correo. Revisa sus condiciones antes de introducir datos.",
        "mode": "Consulta en el sitio del proveedor",
    },
    {
        "id": "cronup",
        "name": "CronUp Leaks",
        "url": "https://leaks.cronup.com/",
        "description": "Fuente externa para revisar filtraciones. Consulta en su sitio el alcance del servicio y sus condiciones antes de introducir datos.",
        "mode": "Consulta en el sitio del proveedor",
    },
)

SOURCE_GUIDES = {
    "xposedornot": {
        "logo": "analysis/providers/xposedornot.ico",
        "initials": "XON",
        "steps": [
            "Para consultar desde VIGIA, introduce tu correo en el formulario y autoriza la búsqueda.",
            "También puedes abrir XposedOrNot y realizar la consulta directamente allí.",
        ],
        "note": "Solo la consulta autorizada desde VIGIA actualiza el estado de esta tarjeta.",
    },
    "hibp": {
        "logo": "analysis/providers/hibp.svg",
        "initials": "HIBP",
        "steps": [
            "Abre Have I Been Pwned e introduce allí el correo que quieres revisar.",
            "Consulta los incidentes y las recomendaciones que muestre el servicio.",
        ],
        "note": "La consulta web es independiente. Solo una API configurada en VIGIA permite mostrar un resultado automático de esta fuente.",
    },
    "hpi": {
        "initials": "HPI",
        "steps": [
            "Abre HPI Identity Leak Checker.",
            "Sigue las instrucciones de su formulario y el mecanismo de entrega del resultado indicado en su sitio.",
        ],
        "note": "VIGIA no recibe el resultado de esta revisión externa.",
    },
    "fsecure": {
        "initials": "F-S",
        "steps": [
            "Abre F-Secure Identity Theft Checker.",
            "Revisa sus condiciones e introduce los datos que solicite para realizar la comprobación.",
            "Consulta el resultado según las instrucciones del proveedor.",
        ],
        "note": "VIGIA no recibe el resultado de esta revisión externa.",
    },
    "malwarebytes": {
        "logo": "analysis/providers/malwarebytes.svg",
        "initials": "MB",
        "steps": [
            "Abre Malwarebytes desde el enlace de esta tarjeta.",
            "Introduce allí el mismo correo que consultaste en VIGIA.",
            "Recibe el código de verificación en ese correo y úsalo solo en el sitio de Malwarebytes.",
            "Consulta el resultado allí después de completar la verificación.",
        ],
        "note": "VIGIA no ha solicitado ni validado un código. No accede a tu buzón ni recibe el resultado de esa revisión.",
    },
    "cronup": {
        "initials": "CR",
        "steps": [
            "Abre CronUp Leaks.",
            "Consulta el alcance y las condiciones del servicio antes de introducir datos.",
            "Sigue las instrucciones de su sitio para realizar la revisión.",
        ],
        "note": "Su cobertura y API no se han verificado. VIGIA no recibe un resultado automático de esta fuente.",
    },
    "ciberlupa": {
        "logo": "analysis/providers/anci.png",
        "initials": "ANCI",
        "steps": [
            "Abre Ciberlupa desde el enlace de esta tarjeta: está seleccionada la verificación por RUT.",
            "Introduce tu RUT directamente en el sitio de ANCI y sigue sus instrucciones.",
            "Revisa el resultado y las recomendaciones que entregue Ciberlupa.",
        ],
        "note": "VIGIA no solicita, envía ni guarda tu RUT. Esta verificación no equivale a la búsqueda del correo y su resultado no vuelve automáticamente a VIGIA.",
    },
}

CHECK_STATES = {
    "found": (
        "danger",
        "!",
        "Filtraciones encontradas",
        "La fuente devolvió registros de exposición para el correo consultado.",
    ),
    "no_records": (
        "success",
        "✓",
        "Sin registros",
        "No hay coincidencias en esta fuente; no garantiza ausencia de filtraciones.",
    ),
    "quota_exceeded": (
        "warning",
        "!",
        "Límite de consultas",
        "La consulta no se completó por un límite de uso.",
    ),
    "timeout": (
        "warning",
        "!",
        "Sin respuesta",
        "El proveedor no respondió dentro del tiempo de espera.",
    ),
    "authentication_error": (
        "neutral",
        "—",
        "Error de acceso",
        "No se pudo acceder a la API configurada.",
    ),
    "access_denied": (
        "neutral",
        "—",
        "Acceso no disponible",
        "El proveedor no permitió completar la consulta.",
    ),
    "invalid_response": (
        "neutral",
        "—",
        "Resultado no válido",
        "La respuesta recibida no permite determinar si existen registros.",
    ),
    "not_configured": (
        "neutral",
        "—",
        "No habilitado",
        "Puedes consultar esta fuente directamente en su sitio.",
    ),
    "unavailable": (
        "neutral",
        "—",
        "No se pudo consultar",
        "No hay un resultado disponible de esta fuente.",
    ),
}


def source_checks(provider, result=None, *, enabled=True):
    """Project actual provider outcomes; an external link never constitutes a check."""
    rows = []
    completed = 0
    for source in SOURCES:
        selected = source["id"] == provider
        if selected and result is not None:
            state = result.get("status", "unavailable")
            tone, symbol, label, detail = CHECK_STATES.get(state, CHECK_STATES["unavailable"])
            completed += int(state in {"found", "no_records"})
            count = len(result.get("breaches", [])) if state == "found" else None
        elif selected and enabled:
            state = "not_checked"
            tone, symbol, label, detail = (
                "pending",
                "○",
                "Sin consultar",
                "Se consultará al enviar el formulario con tu autorización.",
            )
            count = None
        elif source["id"] == "malwarebytes":
            state = "external_verification"
            tone, symbol, label, detail = (
                "warning",
                "—",
                "Verificación en Malwarebytes",
                "Requiere verificar el correo en su sitio. VIGIA no ha solicitado ni validado un código.",
            )
            count = None
        else:
            state = "manual"
            tone, symbol, label, detail = (
                "neutral",
                "—",
                "Revisión manual",
                "No consultado automáticamente. Abre el sitio para realizar su comprobación.",
            )
            count = None
        rows.append(
            {
                **source,
                **SOURCE_GUIDES[source["id"]],
                "state": state,
                "tone": tone,
                "symbol": symbol,
                "label": label,
                "detail": detail,
                "count": count,
                "action": "Abrir y verificar correo"
                if source["id"] == "malwarebytes"
                else "Consultar en su sitio",
            }
        )
    return {
        "rows": rows,
        "completed": completed,
        "total": len(rows),
        "has_result": result is not None,
    }


def lookup_xposedornot(email):
    response = None
    try:
        response = requests.get(
            XON_API + quote(email, safe=""),
            headers={"User-Agent": "VIGIA-Account-Exposure-Check", "Accept": "application/json"},
            timeout=(5, 15),
            allow_redirects=False,
            stream=True,
        )
        if response.status_code not in {200, 404}:
            return {
                "status": {429: "quota_exceeded", 403: "access_denied"}.get(
                    response.status_code, "unavailable"
                )
            }
        body = bytearray()
        for chunk in response.iter_content(chunk_size=65536):
            body.extend(chunk)
            if len(body) > MAX_RESPONSE_BYTES:
                return {"status": "invalid_response"}
        payload = json.loads(body)
        if not isinstance(payload, dict):
            return {"status": "invalid_response"}
        # A generic proxy/route 404 is not proof of absence from the breach database.
        if (
            payload.get("Error") == "Not found"
            and "email" in payload
            and payload["email"] is None
            and "breaches" not in payload
        ):
            return {"status": "no_records", "breaches": []}
        if response.status_code != 200 or payload.get("status") != "success":
            return {"status": "invalid_response"}
        groups = payload.get("breaches")
        if not isinstance(groups, list) or len(groups) != 1 or not isinstance(groups[0], list):
            return {"status": "invalid_response"}
        names = groups[0]
        if (
            not names
            or len(names) > 500
            or any(not isinstance(name, str) or not name.strip() for name in names)
        ):
            return {"status": "invalid_response"}
        return {
            "status": "found",
            "breaches": [
                {"title": name[:200], "date": "", "data_classes": []}
                for name in dict.fromkeys(names)
            ],
        }
    except requests.Timeout:
        return {"status": "timeout"}
    except (requests.RequestException, ValueError, TypeError):
        return {"status": "unavailable"}
    finally:
        if response is not None:
            response.close()


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
        "Este correo aparece en las filtraciones indicadas por {provider}. No demuestra que alguien tenga acceso actualmente a tu cuenta.",
    ),
    "no_records": (
        "neutral",
        "Sin registros en la fuente consultada",
        "{provider} no devolvió registros para este correo. Puede haber filtraciones que no estén incluidas; este resultado no garantiza que la cuenta esté protegida.",
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


def present(result, provider="hibp"):
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
        "message": message.format(
            provider=PROVIDERS.get(provider, {"name": "El proveedor"})["name"]
        ),
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
