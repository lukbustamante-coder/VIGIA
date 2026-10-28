# VIGIA

Portal defensivo en **Python 3.12 y Django 5.2 LTS**, con interfaz en español. Tres módulos: correo **EML**, archivos **PDF, ZIP, DOC/DOCX, XLS/XLSX, PPT/PPTX, ODT/ODS/ODP, TXT, CSV, RTF, PNG y JPEG**, y reputación de **URL HTTP/HTTPS**.

Después de ingresar con SSO, la barra superior permite cambiar entre **Análisis de correo** (`/analisis/correos/`), **Análisis de archivos** (`/analisis/archivos/`) y **Análisis de URL** (`/analisis/urls/`). Cada módulo tiene su formulario e historial independiente. La página inicial abre el módulo de correo. Los usuarios ven sus propios análisis y los administradores los de todos, filtrados por módulo. Consulta [el alcance y la configuración de URLs](docs/urls.md).

En correo y archivos, el área celeste permite elegir un archivo desde el explorador o arrastrarlo sobre la página. Se selecciona un archivo por análisis, con un máximo de 20 MB y los formatos del módulo. El envío se realiza al pulsar «Enviar a analizar»; al cambiar de archivo se desmarcan las autorizaciones de servicios externos para revisarlas de nuevo. La validación de formato, firma y tamaño se mantiene en el servidor aunque JavaScript no esté disponible.

El diseño compartido utiliza la paleta institucional UTEM: azul `#004EAA`, verde `#78BF26`, blanco y grises del manual. Consulta [los criterios de color y contraste](docs/design.md).

Los usuarios autenticados consultan el veredicto de sus propias cargas. Los administradores con el rol OIDC de cliente `vigia-admin` consultan todos los análisis, indicadores de compromiso y evidencia. La aplicación no ofrece acceso anónimo a los análisis ni contraseñas locales.

La pantalla de resultados incluye un resumen visual y actualización automática mientras el trabajo está en cola o en ejecución. Los administradores ven un contador circular de motores maliciosos/total según el reporte real de VirusTotal, el desglose de resultados, SHA-256, tamaño y fechas del archivo. El veredicto general también considera los hallazgos locales y puede diferir de la puntuación de VirusTotal. Los usuarios comunes mantienen únicamente el veredicto. Si no hay reporte o falla la consulta, se muestra «Sin puntuación disponible»; no se inventan cifras. El tamaño, hash del original y fecha del reporte se registran en nuevos análisis; los reportes antiguos pueden mostrar datos no disponibles. Las fechas de esta pantalla se presentan en America/Santiago.

**Estado: primera versión funcional para desarrollo, no un producto certificado ni un motor antivirus completo.** La conexión a tu Keycloak y a proveedores reales queda pendiente de configuración. No se ha validado contra una instalación real de Keycloak 26.4.11 / Red Hat build of Keycloak; el protocolo implementado es OIDC Discovery + Authorization Code + PKCE S256.

## Inicio local

Requiere Linux, Python 3.12+ y `uv`. Usa el checkout existente; no necesitas otro worktree.

```bash
cd /workspace/VIGIA
export UV_CACHE_DIR=/workspace/.cache/uv
uv sync --frozen
cp .env.example .env   # solo si todavía no existe; no sobreescribas tu configuración
chmod 600 .env
```

Configura `VIGIA_SECRET_KEY` con un secreto aleatorio de al menos 50 caracteres en `.env`, sin compartirlo ni versionarlo. Durante la preparación se genera una clave local en el `.env` ignorado si no existe. Carga únicamente un archivo `.env` de confianza:

```bash
set -a
. ./.env
set +a
mkdir -p var/uploads
uv run python manage.py migrate --noinput
uv run python manage.py collectstatic --noinput
uv run python manage.py runserver 127.0.0.1:8000 --noreload
```

En otra terminal, con el mismo entorno y directorio:

```bash
uv run python manage.py scan_worker
```

Antes de configurar SSO se puede abrir la portada y comprobar `/health/`, pero no cargar ni consultar análisis. Esto es intencional. `scan_worker --once` procesa como máximo un trabajo, útil para validación. Usa un único worker con SQLite; para concurrencia usa PostgreSQL.

## Configurar Keycloak al final

Consulta [la guía de SSO](docs/keycloak.md). Variables necesarias: `OIDC_ISSUER`, `OIDC_CLIENT_ID`, `OIDC_CLIENT_SECRET` y `OIDC_REDIRECT_URI`. Introduce los valores secretos mediante variables seguras del despliegue; no los envíes por chat ni los agregues al repositorio.

La autorización administrativa depende de `resource_access.<client-id>.roles` dentro del **ID token firmado**, no de encabezados HTTP, roles del navegador, correo electrónico ni el campo `is_staff`. La sesión termina al caducar el ID token o a los 30 minutos, lo que ocurra antes; no hay refresh automático. La revocación de un rol puede tardar hasta ese vencimiento. Cerrar sesión invalida primero el acceso local y redirige al `end_session_endpoint` de Keycloak. Como no se conserva el ID token, Keycloak puede pedir confirmar el cierre. Debe estar registrado `http://localhost:8000/auth/logout/callback/` en **Valid post logout redirect URIs** para las pruebas (HTTPS y dominio real en producción). `OIDC_POST_LOGOUT_REDIRECT_URI` es opcional y por defecto deriva esa ruta del origen de `OIDC_REDIRECT_URI`; no acepta dominios de retorno diferentes. El siguiente ingreso solicita `prompt=login` hasta completar una autenticación válida, incluso si no fue posible iniciar el cierre del proveedor. Los roles se vuelven a cargar de un ID token nuevo y verificado. El logout de Keycloak puede afectar a otras aplicaciones SSO según su configuración.

## Proveedores opcionales

- **VirusTotal**: `VT_API_KEY`. Consulta primero `GET /api/v3/files/<sha256>` del archivo original. Por defecto no envía muestras. Si el operador habilita `VT_ALLOW_SAMPLE_UPLOAD=true` y el usuario marca la autorización de esa carga, un hash desconocido se envía mediante `POST /api/v3/files` y se consulta `GET /api/v3/analyses/<id>` hasta obtener el reporte. La muestra se comparte con un tercero y puede estar disponible para socios de seguridad según las condiciones de tu cuenta; no habilites este modo para información confidencial sin autorización institucional. Se usa un nombre genérico en el envío, pero el contenido original completo se comparte. No se visitan URL extraídas. Dos o más motores con detección producen `Malicioso`; uno produce `Sospechoso`. Errores, cuotas y cobertura local incompleta pueden producir `No concluyente`.
- **IA para correos**: selecciona `AI_PROVIDER=openai` o `AI_PROVIDER=gemini`. Por defecto recibe solo hallazgos técnicos; permite un informe explicativo para el propietario y los administradores, sin cambiar el veredicto. El envío de encabezados requiere `AI_ALLOW_HEADER_UPLOAD=true` y autorización por carga. No se envían el cuerpo ni los adjuntos a la IA. Consulta [la configuración y los límites](docs/ai.md). Para archivos se conserva la explicación administrativa de OpenAI con `AI_API_KEY` y `AI_MODEL`; Gemini se aplica al módulo de correos.
- **MXToolbox para correos**: `MXTOOLBOX_ENABLED=true` y `MXTOOLBOX_API_KEY`, con autorización por carga, permiten hasta tres consultas DNS de configuración (SPF, DMARC y una clave DKIM). No se envía el EML ni se verifican criptográficamente sus firmas. Las respuestas quedan en evidencia administrativa sin interpretar campos cuyo esquema aún no se ha confirmado. Consulta [la configuración y el diagnóstico](docs/mxtoolbox.md).
- Sin claves, el análisis local funciona y la cobertura de reputación se marca incompleta. No se inventan resultados externos.

Destinos de red: registro Python para instalación, dominio de tu Keycloak para Discovery/token/JWKS, `www.virustotal.com` y `api.openai.com` si habilitas los proveedores. No se visitan los dominios encontrados en las muestras. Conserva verificación TLS y no sigas redirecciones de proveedores.

### Habilitar análisis de muestras desconocidas en VirusTotal

1. Revisa privacidad, términos/licencia y cuotas de VirusTotal antes de habilitar transferencias de contenido.
2. Conserva `VT_API_KEY` en `.env` o en el gestor de secretos y añade `VT_ALLOW_SAMPLE_UPLOAD=true`. Configura la misma política y clave en web y worker; por defecto la política es `false`.
3. Detén web/worker cuando no haya trabajos en curso, actualiza el checkout y ejecuta `bash scripts/setup.sh` para aplicar las migraciones. Carga nuevamente `.env` en ambas terminales y reinicia los procesos.
4. En cada carga autorizada marca «Autorizar el envío de este archivo o correo a VirusTotal si no tiene reporte». La casilla empieza desmarcada. La política global por sí sola no autoriza envíos; un checkbox falsificado con la política desactivada se rechaza.
5. Si el hash ya existe, se reutiliza el reporte y no se envía la muestra. Si no existe, se envía una sola vez por trabajo, pasa a `waiting_vt` y se consulta aproximadamente cada 30 segundos (60 tras un 429), liberando el worker entre consultas. El resultado se actualiza automáticamente al terminar. La espera máxima es de 30 minutos o 60 consultas; pueden aplicarse límites más restrictivos del plan.
6. Al obtener el identificador del análisis, se elimina la copia local de la muestra; las consultas posteriores usan el identificador y la evidencia ya guardada. Reiniciar el worker no vuelve a enviar una muestra ya registrada. Un fallo de conexión durante el envío puede dejar incierto si el proveedor la recibió; no se reintenta automáticamente ese envío.

Los permisos administrativos siguen controlando estadísticas, hashes, IOC e identificadores del proveedor. Se auditan autorización, intento de envío, recepción del identificador y finalización. La auditoría local no es una transacción atómica con VirusTotal ni reemplaza un registro externo inmutable. La IA no recibe la muestra completa: solo puede recibir los encabezados seleccionados del EML cuando existe autorización independiente para ello.

## Qué analiza

Hash SHA-256, firma antivirus **de prueba EICAR**, coherencia de formatos, macros Office, relaciones externas OOXML, acciones PDF visibles, objetos RTF, fórmulas CSV, ejecutables embebidos, diferencias From/Reply-To y contenido activo HTML de EML. Extrae URL, dominio, IPv4, email y hash, con límites de cantidad. Los enlaces se presentan como texto escapado, no como enlaces navegables.

En correos, una diferencia de dominios entre `From` y `Reply-To` se registra como información para el administrador: es habitual en plataformas de envío y no basta por sí sola para marcar suplantación. El contenido activo se busca como etiquetas y atributos reales en partes `text/html`, sin ejecutarlos; ejemplos de código en texto plano, comentarios HTML o texto escapado no activan esa regla. Los adjuntos y las detecciones de VirusTotal conservan su evaluación independiente. Esto no verifica la autenticidad del remitente ni demuestra que el correo sea seguro. Para investigar un posible falso positivo, ejecuta `uv run python manage.py diagnose_analysis --limit 5` y revisa los hallazgos; después de actualizar, vuelve a cargar el EML para obtener un análisis nuevo.

Los ZIP se inspeccionan en memoria sin extraer a disco: máximo 100 entradas globales, 20 MB expandidos, relación de compresión 100:1 y profundidad máxima 2. Se detectan rutas peligrosas y archivos cifrados. Las cargas se limitan a 20 MB durante la recepción; se valida extensión y estructura/firma, sin confiar en el Content-Type del cliente.

Veredictos: **Malicioso**, **Sospechoso**, **Sin indicios detectados** y **No concluyente**. `Sin indicios` no significa seguro. Los PDF se inspeccionan estructuralmente con pypdf: se resuelven objetos referenciados y streams comprimidos, se buscan acciones activas y se aplican límites de objetos, profundidad y descompresión. No se ejecutan acciones, renderizan páginas ni decodifican imágenes. PDF cifrados, estructuras inválidas y límites alcanzados conservan cobertura incompleta. No hay sandbox de detonación, ClamAV, YARA, validación criptográfica SPF/DKIM/DMARC ni garantía contra malware desconocido. Los `Authentication-Results` de un EML subido no se consideran confiables. Los IOC se obtienen por análisis estático acotado, no por extracción forense exhaustiva.

## Diagnosticar «No concluyente»

«Completado» significa que terminó el proceso; no garantiza que se dispusiera de toda la evidencia. Un PDF/DOCX válido puede quedar no concluyente si VirusTotal desconoce el hash, el worker no cargó la clave, se agotó la cuota o falló la consulta. La cobertura local y la reputación se registran por separado en nuevos análisis. Las razones solo se presentan a administradores; los usuarios mantienen el veredicto.

En una terminal de operación con las variables cargadas, ejecuta `uv run python manage.py diagnose_analysis --limit 5` o `uv run python manage.py diagnose_analysis UUID_DEL_ANALISIS`. No imprime claves, nombres de archivos ni IOC. Funciona también con reportes anteriores y muestra el diagnóstico disponible; los errores genéricos antiguos no pueden clasificarse retrospectivamente y requieren repetir la carga.

| Estado de VirusTotal | Acción |
| --- | --- |
| `not_configured` | Cargar `.env` en la terminal del worker y reiniciarlo |
| `authentication_error` / `access_denied` | Revisar clave y permisos de la cuenta |
| `quota_exceeded` | Esperar la recuperación de la cuota según el plan y volver a analizar |
| `timeout` / `unavailable` | Comprobar conectividad/proxy/TLS y volver a analizar |
| `unknown_hash` | No existe reporte y no se autorizó el envío: habilitar el modo de muestras y marcar la autorización en una nueva carga si está permitido |
| `queued` / `in-progress` | La muestra autorizada está esperando o procesándose en VirusTotal; mantener el worker activo |
| `analysis_timeout` | No llegó un reporte dentro de los límites de espera; se conserva la evidencia local |
| `invalid_response` / `no_results` | No hay resultados de motores utilizables; conservar «No concluyente» |

Si la reputación está disponible, los hallazgos locales pueden seguir haciendo la cobertura incompleta (cifrado, formato no soportado, límites). La versión inicial marcaba todos los PDF como inspección limitada; actualiza y vuelve a cargar esos PDF para usar la inspección estructural. Los reportes guardados no cambian automáticamente.

## Pruebas

Con `.env` cargado:

```bash
uv run pytest -q
uv run ruff check .
uv run ruff format --check .
uv run python manage.py check
VIGIA_DEBUG=false uv run python manage.py check --deploy --fail-level WARNING
```

Las pruebas verifican carga → worker real → resultado → borrado de la muestra, EML/adjuntos, controles de acceso y CSRF, escape XSS, ZIP peligrosos, XML con entidades, integraciones simuladas y tokens OIDC RSA firmados con rechazos de emisor/audiencia/nonce/caducidad incorrectos. No equivalen a pruebas con tu tenant y credenciales reales.

## Despliegue

1. `VIGIA_DEBUG=false`; secreto estable y único; hosts y `VIGIA_CSRF_ORIGINS` explícitos; SSO y callback HTTPS exactos.
2. PostgreSQL mediante `PGHOST`, `PGDATABASE`, `PGUSER`, `PGPASSWORD`, `PGPORT` y `PGSSLMODE=verify-full`. Instala la CA del servidor en el almacén de confianza de libpq si hace falta. SQLite es solo el valor inicial para desarrollo.
3. Ejecuta migraciones y `collectstatic`, luego `uv run gunicorn vigia.wsgi:application --bind 127.0.0.1:8000 --workers 2 --timeout 45`. WhiteNoise sirve los recursos estáticos públicos; nunca las muestras.
4. Supervisa `scan_worker` como proceso separado, mismo almacenamiento privado y base de datos. Se ejecuta en Linux: cada paso usa un subproceso limitado a 90 s de tiempo total, 30 s CPU, 512 MiB de memoria y 64 descriptores. La espera de VirusTotal se persiste y reanuda sin mantener un subproceso vivo durante minutos. `scan_worker --once` procesa como máximo un paso (inspección/envío o consulta pendiente). Los fallos conservan las detecciones locales ya registradas; sin evidencia concluyente producen `No concluyente`. Estos límites **no constituyen una sandbox de seguridad del sistema operativo**.
5. Usa proxy TLS confiable con límite de cuerpo 21 MB, timeouts, cuotas globales de disco y rate limiting por identidad/IP. Habilita `VIGIA_TRUST_PROXY=true` solo si el proxy elimina y reemplaza `X-Forwarded-Proto`. No expongas Gunicorn directamente. No configures origen comodín.
6. Almacena `var/uploads` fuera del contenido público, con permisos restrictivos, cifrado de disco y backups protegidos. Las muestras se borran al terminar el análisis; los errores también intentan borrarlas. Programa diariamente `uv run python manage.py purge_submissions`: elimina resultados de más de 30 días, auditoría de más de 90 y muestras huérfanas de más de 10 minutos. Sin este scheduler, esa retención de resultados no se ejecuta sola.
7. Aísla web y scanner en contenedores/procesos con usuarios mínimos, filesystem restringido, seccomp/AppArmor, sin acceso del scanner a secretos SSO/DB ni a redes internas, y egress solo a proveedores permitidos. El subproceso recibe únicamente variables necesarias para proveedores, proxy y TLS.
8. Centraliza auditoría y métricas (cola, latencia, cuotas, fallos), aplica backups/restauración y un procedimiento de incidentes. El registro local no es inmutable ni reemplaza un SIEM.

Antes de producción: prueba de SSO real con roles usuario/admin y revocación, validación de cuotas reales de API, análisis de dependencias, pruebas de carga y revisión de seguridad independiente. Lee [el modelo de seguridad](docs/security.md).
