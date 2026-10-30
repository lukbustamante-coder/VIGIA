# Reportes por correo a soporte

En el detalle de correos, archivos y URL con resultado malicioso, sospechoso o no concluyente aparece **Reportar**. Solo la persona propietaria puede enviar el reporte; ser administrador no permite reportar en su nombre. Los trabajos pendientes y los resultados sin indicios no ofrecen esta acción. No hay envíos automáticos por detectar una amenaza: se requiere pulsar el botón.

Los destinatarios están fijados en el servidor:

- `soporte.sisei@utem.cl`
- `sisei-infraestructura@utem.cl`

El correo contiene el identificador del análisis, nombre y correo de contacto de quien reporta, módulo, resultado, fechas, nombre original, URL completa cuando corresponda y evidencia técnica JSON. Para archivos y correos incluye el original como adjunto binario; el EML conserva sus propios adjuntos. No se ejecuta ni se renderiza. El asunto advierte que es un reporte VIGIA y el cuerpo indica tratar la muestra como potencialmente maliciosa. Los destinatarios deben revisarla en un entorno aislado. El nombre de la muestra adjunta es genérico; el nombre original se informa en el cuerpo.

## Configurar SMTP institucional

Todavía no se conocen los datos del SMTP de esta instalación. `.env.example` incluye un bloque listo para copiar a `.env` y completar localmente. No se modifican automáticamente archivos `.env` existentes. No compartas la contraseña ni la subas al repositorio.

```dotenv
# Activar cuando TI haya confirmado servidor y remitente.
REPORT_MAIL_ENABLED=false
EMAIL_HOST=
EMAIL_PORT=587
EMAIL_USE_TLS=true
EMAIL_USE_SSL=false
EMAIL_HOST_USER=
EMAIL_HOST_PASSWORD=
DEFAULT_FROM_EMAIL=
```

- `EMAIL_HOST`: servidor o relay institucional accesible desde el servidor VIGIA.
- Puerto 587: normalmente `EMAIL_USE_TLS=true`, `EMAIL_USE_SSL=false` (STARTTLS).
- Puerto 465: normalmente `EMAIL_USE_TLS=false`, `EMAIL_USE_SSL=true`.
- Relay sin autenticación: usuario y contraseña vacíos si TI lo autoriza. Si TI indica conexión sin TLS en la red institucional, ambas opciones van en `false`. Nunca activar las dos a la vez.
- `DEFAULT_FROM_EMAIL`: dirección remitente autorizada por TI. El correo del usuario se usa en `Reply-To`, no se suplanta como remitente.
- Cambia `REPORT_MAIL_ENABLED=true` cuando estén completos los datos. Mientras falten, el botón aparece deshabilitado y VIGIA no afirma haber enviado nada.

El transporte de producción es SMTP con tiempo de espera de 30 segundos y verificación TLS predeterminada. Las muestras admiten hasta 20 MB, pero el relay debe aceptar el tamaño del mensaje codificado: base64 aumenta el tamaño aproximadamente un tercio, más la evidencia JSON. Si el relay lo rechaza, el reporte no se presenta como enviado y no se omiten los adjuntos silenciosamente. Confirmar el límite de mensajes con TI.

Después de configurar:

```bash
cd ~/VIGIA
git pull --ff-only origin main
bash scripts/setup.sh
```

Reinicia servidor y `scan_worker` con `.env` cargado en ambas terminales. No hace falta otro proceso: el worker atiende también la cola de reportes. `uv run python manage.py scan_worker --once` procesa como máximo un reporte y un trabajo de análisis. El script de actualización aplica la migración `0007_incidentreport` y recoge los recursos estáticos.

## Datos de contacto y estados

Se utiliza el claim `email` sintácticamente válido del ID token SSO ya validado, solo como información de contacto y sin conceder permisos. Si está disponible se muestra precargado y deshabilitado. En sesiones antiguas, o si el SSO no entrega un correo, el formulario solicita una dirección de contacto. Esa dirección es declarada por la persona; no se afirma que haya pasado una verificación de buzón. Esto no restringe ni cambia la búsqueda editable de filtraciones.

El estado de reporte se conserva aparte del análisis, por lo que no borra el veredicto ni su evidencia. El historial muestra el estado del reporte:

- **Reporte en cola / Enviando reporte**: solicitud registrada, pendiente de envío. La pantalla consulta su estado automáticamente.
- **Reportado**: el relay aceptó el mensaje dirigido a ambas casillas. No demuestra entrega final a los buzones ni apertura por los equipos. Texto: «Tu reporte fue enviado. El equipo revisará el caso y te contactará para orientarte sobre los próximos pasos o informarte el resultado de su revisión».
- **Reporte no enviado**: fallo conocido; permite reintentar manualmente, con un máximo de tres intentos.
- **Envío por confirmar**: desconexión, timeout, aceptación parcial de destinatarios o interrupción del worker después de iniciar el envío. No se reenvía automáticamente porque podría duplicar el mensaje. Soporte debe confirmar en el relay el identificador de análisis/Message-ID antes de resolver el estado.

Una relación única por análisis y bloqueo transaccional en PostgreSQL evitan duplicar solicitudes por clics repetidos. El worker reclama cada reporte antes de enviarlo y no reintenta automáticamente. El Message-ID estable por análisis facilita rastrearlo. No hay garantía de entrega exactamente una vez entre la base de datos y SMTP. La aceptación parcial se distingue de éxito para no afirmar envío a ambas casillas. Los errores se presentan sin exponer respuestas SMTP, credenciales ni contenido.

## Conservación de originales

Las nuevas cargas EML/archivo guardan una copia privada en `VIGIA_STORAGE/report-samples/<UUID>`, directorio 0700 y archivo 0600. No existe ruta HTTP para descargarla. Se elimina al terminar un análisis sin indicios. Los originales reportables permanecen hasta que expire su análisis; no se reutilizan para reenvíos a VirusTotal. El worker sigue borrando la copia de trabajo inicial.

Los análisis antiguos ya no conservan el original. Su formulario exige volver a seleccionarlo y valida formato, tamaño y coincidencia SHA-256 con el análisis antes de adjuntarlo. Si el análisis no conserva un hash, se debe cargar y analizar el archivo de nuevo. No se recuperan archivos eliminados ni se envía una muestra diferente.

Programa diariamente `uv run python manage.py purge_submissions`. Elimina resultados de más de 30 días, sus reportes y correos de contacto asociados, así como sus copias privadas y muestras huérfanas. La auditoría se conserva hasta 90 días sin direcciones, nombres de incidentes ni cuerpos de mensajes. Sin programar el comando la retención no se ejecuta sola. El correo enviado y sus adjuntos quedan sujetos a la retención de los buzones institucionales, independiente de VIGIA. Proteger disco, backups y acceso al relay de acuerdo con las políticas institucionales.

## Validación

Las pruebas usan el backend de correo en memoria y respuestas SMTP simuladas; no envían mensajes reales. Cubren propietarios, CSRF, datos de contacto, adjuntos exactos, reingreso de originales antiguos, conservación y purga, estados, duplicados, reintentos, fallos conocidos y aceptación parcial. La verificación del relay institucional queda pendiente de completar sus datos y realizar una prueba controlada de entrega a ambas casillas.
