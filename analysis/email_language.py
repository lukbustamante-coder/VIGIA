"""Plain-language explanations of recorded evidence, independent of AI availability."""

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
