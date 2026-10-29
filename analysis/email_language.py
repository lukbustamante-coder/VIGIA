"""Plain-language explanations of recorded evidence, independent of AI availability."""

import ipaddress
import re
from email.utils import getaddresses

AUTH_METHODS = {
    "spf": (
        "Autorización del servidor de envío (SPF)",
        "Comprueba si el servidor que envía el mensaje está autorizado por el dominio usado "
        "para enviarlo. Ayuda a detectar envíos no autorizados, pero no confirma por sí solo "
        "la identidad de la persona ni que el contenido sea legítimo.",
    ),
    "dkim": (
        "Firma digital del correo (DKIM)",
        "Permite comprobar una firma añadida por un dominio de correo. Cuando se verifica "
        "correctamente, ayuda a confirmar que las partes firmadas no cambiaron desde la firma "
        "y que se utilizó una clave autorizada por ese dominio. Tener una firma no significa "
        "que se haya validado ni que el mensaje sea seguro.",
    ),
    "dmarc": (
        "Coherencia del dominio del remitente (DMARC)",
        "Relaciona el dominio que ves en el remitente con el dominio comprobado mediante SPF "
        "o DKIM. Para superar esta comprobación, al menos uno de esos mecanismos debe "
        "validarse y coincidir con el dominio visible según sus reglas. Ayuda a detectar "
        "suplantaciones del dominio; no garantiza que una solicitud sea legítima.",
    ),
}

SHORT_DEFINITIONS = {
    "spf": "SPF indica qué servidores pueden enviar correos en nombre de un dominio.",
    "dkim": "DKIM es una firma digital que permite comprobar el dominio firmante y si las partes firmadas cambiaron.",
    "dmarc": "DMARC comprueba si el dominio del remitente es coherente con el validado por SPF o DKIM.",
}

AUTH_RESULTS = {
    "pass": (
        "Satisfactorio según el correo (PASS)",
        "El registro del correo declara que esta comprobación fue satisfactoria. "
        "VIGIA no la ha repetido ni ha confirmado que ese registro provenga de un servidor confiable.",
    ),
    "fail": (
        "No superado según el correo (FAIL)",
        "El registro declara que esta comprobación no se superó. Es un dato que requiere "
        "revisión; por sí solo no demuestra que el mensaje sea malicioso, ya que también "
        "pueden influir errores de configuración o cambios durante su entrega.",
    ),
    "softfail": (
        "Autorización no confirmada (SOFTFAIL)",
        "El registro indica que el servidor de envío no quedó autorizado de forma concluyente. "
        "Conviene revisar el mensaje y la configuración del dominio antes de confiar en él.",
    ),
    "neutral": (
        "Sin una conclusión declarada (NEUTRAL)",
        "El registro no declara un resultado que permita confirmar o rechazar esta comprobación.",
    ),
    "none": (
        "Sin una comprobación aplicable declarada (NONE)",
        "El registro declara que no hay un resultado aplicable para este mecanismo. "
        "No equivale a superar la comprobación ni demuestra un ataque.",
    ),
    "temperror": (
        "Error temporal declarado (TEMPERROR)",
        "El registro indica que un problema temporal impidió completar la comprobación. "
        "No debe interpretarse como un resultado satisfactorio.",
    ),
    "permerror": (
        "Error de configuración o evaluación declarado (PERMERROR)",
        "El registro indica un problema que impidió evaluar correctamente este mecanismo. "
        "El equipo de seguridad puede revisar la configuración involucrada.",
    ),
}


def explain_method(method, raw_values):
    values = list(
        dict.fromkeys(
            value for value in raw_values if isinstance(value, str) and value in AUTH_RESULTS
        )
    )
    title, description = AUTH_METHODS[method]
    if not values:
        label = "No hay resultado registrado"
        interpretation = (
            "No se encontró un resultado reconocido para este mecanismo en los encabezados "
            "conservados. No se puede concluir que haya superado o fallado la comprobación."
        )
    elif len(values) == 1:
        label, interpretation = AUTH_RESULTS[values[0]]
    else:
        label = "Varios resultados declarados: " + ", ".join(value.upper() for value in values)
        interpretation = (
            "Hay resultados diferentes en los registros del correo. Pueden proceder de "
            "distintos pasos de su entrega; no se resumen como una única validación "
            "satisfactoria. Requieren revisar su contexto y procedencia."
        )
    return {
        "name": method.upper(),
        "declared": ", ".join(value.upper() for value in values) or "No consta",
        "title": title,
        "description": description,
        "short_definition": SHORT_DEFINITIONS[method],
        "result_label": label,
        "interpretation": interpretation,
    }


def explain_routing(headers):
    count = headers.get("received_count")
    introduction = (
        "Los registros de entrega describen los servidores por los que declara haber pasado "
        "el mensaje, de forma parecida a las etapas de un envío postal. "
    )
    if type(count) is int and count > 0:
        observation = (
            "Se registró una etapa de entrega en los encabezados. "
            if count == 1
            else f"Se registraron {count} etapas de entrega en los encabezados. "
        )
    elif count == 0:
        observation = "No se registraron etapas de entrega en los encabezados examinados. "
    else:
        observation = "Este análisis no conserva un recuento de las etapas de entrega. "
    limitation = (
        "Estos datos pueden modificarse en un archivo de correo. Sin una cadena de servidores "
        "confiable, no permiten confirmar el equipo de origen, su propietario ni la identidad "
        "de quien envió el mensaje."
    )
    if headers.get("truncated"):
        limitation += " Parte de los encabezados quedó fuera del límite de revisión."
    return introduction + observation + limitation


def explain_content(details, headers):
    links = details.get("iocs", {}).get("urls", [])
    text = (
        "Se registraron direcciones web en el mensaje o sus archivos asociados. "
        "Se extrajeron sin abrirlas; no se comprobó el contenido de las páginas ni el destino "
        "actual de posibles redirecciones. "
        if links
        else "No se registraron direcciones web con la extracción automática disponible. "
        "Esto no descarta enlaces ocultos o contenido que no se pudo interpretar. "
    )
    count = headers.get("attachment_count")
    if type(count) is int and count > 0:
        text += (
            "Se identificó un archivo adjunto o una imagen asociada al correo. "
            if count == 1
            else f"Se identificaron {count} archivos adjuntos o imágenes asociadas al correo. "
        )
    elif count == 0:
        text += "No se identificaron partes con nombre de archivo adjunto. "
    else:
        text += "Este registro no detalla por separado la cantidad de archivos adjuntos. "
    text += (
        "La revisión local de formatos admitidos busca señales sin ejecutar los archivos. "
        "El texto del mensaje no se ha evaluado para detectar engaños o solicitudes fraudulentas. "
    )
    if details.get("coverage", {}).get("local_complete") is not True:
        text += "La cobertura local no está confirmada como completa; no puede afirmarse que todo el contenido se haya revisado. "
    text += "La ausencia de hallazgos no garantiza que los enlaces o adjuntos sean seguros."
    return text


# These summaries compare recorded values only; they do not resolve DNS or verify signatures.
def _domain(value):
    addresses = getaddresses([value])
    domains = set()
    for _, address in addresses:
        candidate = address.rsplit("@", 1)[-1].rstrip(".").lower()
        if re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?", candidate):
            if "." in candidate and all(part for part in candidate.split(".")):
                domains.add(candidate)
    return next(iter(domains)) if len(domains) == 1 else ""


def _header_domain(selected, name):
    values = selected.get(name, [])
    return _domain(values[0]) if len(values) == 1 and isinstance(values[0], str) else ""


def concise_evidence(headers, methods):
    selected = headers.get("selected") or {}
    sender = _header_domain(selected, "From")
    sender_text = (
        f"el remitente {sender}" if sender else "el remitente, cuyo dominio no pudo determinarse"
    )
    ips = []
    for value in selected.get("Received", [])[:10]:
        for candidate in re.findall(r"\[([^\]]{1,64})\]", value):
            try:
                ip = ipaddress.ip_address(re.sub(r"^IPv6:", "", candidate, flags=re.I))
            except ValueError:
                continue
            if ip.is_global and str(ip) not in ips:
                ips.append(str(ip))
    if ips:
        shown = ", ".join(ips[:5]) + (" y otras" if len(ips) > 5 else "")
        routing = f"Se encontraron las IP públicas {shown} en la ruta del correo de {sender_text}. No se comprobó que pertenezcan a su dominio."
    else:
        routing = f"No se identificaron IP públicas en los registros de entrega conservados para {sender_text}. No se pudo comprobar su relación con el dominio."
    if headers.get("truncated"):
        routing += " Los encabezados están incompletos."

    envelope = _header_domain(selected, "Return-Path")
    signatures = selected.get("DKIM-Signature", [])
    signers = list(
        dict.fromkeys(
            domain
            for signature in signatures[:10]
            if isinstance(signature, dict)
            if (domain := _domain(signature.get("d", "")))
        )
    )
    for method in methods:
        name = method["name"].lower()
        declared = method["declared"]
        result = (
            "No hay resultado registrado."
            if declared == "No consta"
            else f"El correo declara {declared}."
        )
        if declared == "PASS":
            result = {
                "spf": "El correo declara que el servidor estaba autorizado para enviar (PASS).",
                "dkim": "El correo declara que la firma digital era válida (PASS).",
                "dmarc": result,
            }[name]
        elif declared == "FAIL":
            result = {
                "spf": "El correo declara que el servidor no superó la comprobación de autorización (FAIL).",
                "dkim": "El correo declara que la firma digital no superó la comprobación (FAIL).",
                "dmarc": result,
            }[name]
        elif declared not in {"PASS", "FAIL", "No consta"}:
            result += " No permite confirmar una comprobación satisfactoria."
        if name == "spf":
            context = (
                f"El dominio de envío registrado en Return-Path es {envelope}."
                if envelope
                else "No consta un único dominio de envío en Return-Path."
            )
            if sender and envelope:
                context += (
                    f" Ese dominio coincide exactamente con el del remitente ({sender})."
                    if sender == envelope
                    else f" Ese dominio difiere del remitente ({sender}); esto puede ocurrir con plataformas de envío y no implica fraude."
                )
        elif name == "dkim":
            context = (
                f"La firma indica el dominio {', '.join(signers[:5])}."
                if signers
                else "No consta un dominio de firma identificable."
            )
            if sender and signers:
                context += (
                    f" Una firma usa el mismo dominio que el remitente ({sender})."
                    if sender in signers
                    else f" Los dominios de firma observados difieren del remitente ({sender}); la diferencia por sí sola no demuestra suplantación."
                )
        else:
            context = f"Se revisó el resultado de coherencia entre {sender_text} y los dominios usados al enviar o firmar."
            if declared == "PASS":
                result = "El correo declara PASS: informa que al menos uno de esos dominios cumple las reglas de coincidencia con el remitente."
            elif declared == "FAIL":
                result = "El correo declara FAIL: informa que no se cumplieron las reglas de coincidencia con el remitente."
        method["summary"] = f"{context} {result}"
    return routing


def concise_content(details, headers):
    links = details.get("iocs", {}).get("urls", [])
    count = headers.get("attachment_count")
    parts = [f"Se extrajeron {len(links)} enlaces sin abrirlos."]
    parts.append(
        f"Se identificaron {count} adjuntos o imágenes asociadas."
        if type(count) is int and count >= 0
        else "No consta la cantidad de adjuntos."
    )
    parts.append("No se evaluó si el texto intenta engañar al destinatario.")
    if details.get("coverage", {}).get("local_complete") is not True:
        parts.append("La revisión local del contenido no está confirmada como completa.")
    return " ".join(parts)
