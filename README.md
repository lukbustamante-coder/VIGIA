# VIGIA

Portal defensivo en **Python 3.12 y Django 5.2 LTS**, con interfaz en español. Dos módulos: correo **EML** y archivos **PDF, ZIP, DOC/DOCX, XLS/XLSX, PPT/PPTX, ODT/ODS/ODP, TXT, CSV, RTF, PNG y JPEG**.

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

La autorización administrativa depende de `resource_access.<client-id>.roles` dentro del **ID token firmado**, no de encabezados HTTP, roles del navegador, correo electrónico ni el campo `is_staff`. La sesión termina al caducar el ID token o a los 30 minutos, lo que ocurra antes; no hay refresh automático. La revocación de un rol puede tardar hasta ese vencimiento. Cerrar sesión termina la sesión local, no la sesión global de Keycloak.

## Proveedores opcionales

- **VirusTotal**: `VT_API_KEY`. Consulta `GET /api/v3/files/<sha256>` del archivo original. Nunca sube muestras, adjuntos o correos; no solicita análisis de URLs. Aun un hash puede revelar la posesión de un archivo. Respeta términos, licencia y cuotas de tu cuenta. Dos o más motores con detección producen `Malicioso`; uno produce `Sospechoso`. Un hash desconocido, un fallo o una cuota agotada producen cobertura incompleta.
- **IA**: `AI_API_KEY` y, opcionalmente, `AI_MODEL`. Adaptador inicial a OpenAI. Recibe solo mensajes fijos de detectores y estados booleanos, nunca el archivo, cuerpo EML, IOC o nombre original. Su explicación se muestra únicamente a administradores y no cambia el veredicto. No tiene herramientas ni acceso a enlaces.
- Sin claves, el análisis local funciona y la cobertura de reputación se marca incompleta. No se inventan resultados externos.

Destinos de red: registro Python para instalación, dominio de tu Keycloak para Discovery/token/JWKS, `www.virustotal.com` y `api.openai.com` si habilitas los proveedores. No se visitan los dominios encontrados en las muestras. Conserva verificación TLS y no sigas redirecciones de proveedores.

## Qué analiza

Hash SHA-256, firma antivirus **de prueba EICAR**, coherencia de formatos, macros Office, relaciones externas OOXML, acciones PDF visibles, objetos RTF, fórmulas CSV, ejecutables embebidos, diferencias From/Reply-To y contenido activo HTML de EML. Extrae URL, dominio, IPv4, email y hash, con límites de cantidad. Los enlaces se presentan como texto escapado, no como enlaces navegables.

Los ZIP se inspeccionan en memoria sin extraer a disco: máximo 100 entradas globales, 20 MB expandidos, relación de compresión 100:1 y profundidad máxima 2. Se detectan rutas peligrosas y archivos cifrados. Las cargas se limitan a 20 MB durante la recepción; se valida extensión y estructura/firma, sin confiar en el Content-Type del cliente.

Veredictos: **Malicioso**, **Sospechoso**, **Sin indicios detectados** y **No concluyente**. `Sin indicios` no significa seguro. Un PDF no se desofusca ni se interpreta por completo; las imágenes no se decodifican. No hay sandbox de detonación, ClamAV, YARA, validación criptográfica SPF/DKIM/DMARC ni garantía contra malware desconocido. Los `Authentication-Results` de un EML subido no se consideran confiables. Los IOC se obtienen por análisis estático acotado, no por extracción forense exhaustiva.

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
4. Supervisa `scan_worker` como proceso separado, mismo almacenamiento privado y base de datos. Se ejecuta en Linux: cada análisis usa un subproceso limitado a 90 s de tiempo total, 30 s CPU, 512 MiB de memoria y 64 descriptores. Los fallos y los trabajos interrumpidos producen `No concluyente`. Estos límites **no constituyen una sandbox de seguridad del sistema operativo**.
5. Usa proxy TLS confiable con límite de cuerpo 21 MB, timeouts, cuotas globales de disco y rate limiting por identidad/IP. Habilita `VIGIA_TRUST_PROXY=true` solo si el proxy elimina y reemplaza `X-Forwarded-Proto`. No expongas Gunicorn directamente. No configures origen comodín.
6. Almacena `var/uploads` fuera del contenido público, con permisos restrictivos, cifrado de disco y backups protegidos. Las muestras se borran al terminar el análisis; los errores también intentan borrarlas. Programa diariamente `uv run python manage.py purge_submissions`: elimina resultados de más de 30 días, auditoría de más de 90 y muestras huérfanas de más de 10 minutos. Sin este scheduler, esa retención de resultados no se ejecuta sola.
7. Aísla web y scanner en contenedores/procesos con usuarios mínimos, filesystem restringido, seccomp/AppArmor, sin acceso del scanner a secretos SSO/DB ni a redes internas, y egress solo a proveedores permitidos. El subproceso recibe únicamente variables necesarias para proveedores, proxy y TLS.
8. Centraliza auditoría y métricas (cola, latencia, cuotas, fallos), aplica backups/restauración y un procedimiento de incidentes. El registro local no es inmutable ni reemplaza un SIEM.

Antes de producción: prueba de SSO real con roles usuario/admin y revocación, validación de cuotas reales de API, análisis de dependencias, pruebas de carga y revisión de seguridad independiente. Lee [el modelo de seguridad](docs/security.md).
