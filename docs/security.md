# Modelo y controles de seguridad

## Límites de confianza

El navegador, archivos, nombres, metadatos EML, ZIP/XML y respuestas de IA son datos no confiables. Los únicos permisos administrativos provienen de un rol en un ID token verificado. La interfaz, el API JSON y las vistas aplican control de propietario/rol en el servidor. No existe descarga pública de muestras. El análisis local es estático: no ejecuta archivos, macros, HTML ni enlaces. El envío a VirusTotal está desactivado por defecto y requiere política explícita del operador y autorización por carga; el proveedor puede procesar y compartir la muestra según las condiciones de la cuenta. No se afirma que sus motores sean exclusivamente estáticos.

Se guardan en la base de datos identificador de usuario pseudónimo ligado al issuer/sub, nombre del archivo, estado, veredicto, IOC, hallazgos y auditoría. Los IOC y los nombres pueden contener datos personales: acceso restringido, retención, cifrado y políticas internas siguen siendo necesarios. Las consultas a terceros son opcionales.

Cuando se habilitan muestras, se conservan autorización, identificador de análisis y estado de espera en la base de datos; no se devuelven detalles del proveedor a usuarios comunes. Solo se envía el original autorizado, no se recorren adjuntos para compartirlos por separado. El identificador remoto se valida antes de usarlo en un endpoint fijo. Los redirects de API se rechazan y se conserva la verificación TLS. La muestra local se elimina tras la fase de inspección/envío; los pasos de polling no contienen ni reenvían el archivo. Un timeout de subida puede ocurrir después de que el tercero reciba contenido: la UI y auditoría no deben interpretarse como prueba de ausencia de transferencia. Las cuotas y la latencia no se resuelven cambiando la clasificación.

## Relación con OWASP Top 10

Esta es una guía de diseño, no una certificación de cumplimiento. Se utilizan las categorías 2021 como referencia estable y controles relevantes para cargas de archivos, APIs y uso de IA.

| Riesgo | Control implementado | Control operativo o pendiente |
| --- | --- | --- |
| A01 Control de acceso roto | Login obligatorio, propiedad por consulta, rol cliente firmado, ausencia de IOC en contexto/API de usuarios | Verificar roles y tenant reales; revisar scopes de Keycloak |
| A02 Fallos criptográficos | HTTPS en producción, cookies Secure/HttpOnly/SameSite, TLS verificado a proveedores, sin tokens OIDC persistentes | TLS del proxy, secretos gestionados, cifrado de disco y backups |
| A03 Inyección | ORM, autoescape, sin shell ni ejecución de contenido, XML con defusedxml, IOC como texto | Revisiones y pentest; aislamiento OS para parsers |
| A04 Diseño inseguro | Veredicto inconcluso ante cobertura insuficiente, IA sin permisos ni decisión, inspección acotada | Política de privacidad, modelo de amenazas y aceptación de riesgo |
| A05 Configuración insegura | DEBUG desactivado por defecto, CSP restrictiva, HSTS, frame-ancestors, sin CORS abierto | Hosts/origins/proxy/egress explícitos, `check --deploy` |
| A06 Componentes vulnerables | Versiones resueltas en uv.lock, sync --frozen, TLS/checksums de instalación | Monitorizar CVE, escáner periódico y actualización del lock |
| A07 Fallos de identificación | Authorization Code, PKCE S256, state, nonce, firma/JWKS, issuer/audience/exp, rotación de sesión | MFA y antifuerza bruta en SSO; probar la distribución exacta |
| A08 Integridad | Sin extracción en disco, archivos fuera del webroot, extensiones/firma/estructura, sin deserialización arbitraria | CI protegida, artefactos firmados, permisos y backups |
| A09 Logging y monitorización | Auditoría de login/logout/cargas/consulta de IOC, fallos sin contenido sensible al usuario | SIEM inmutable, alertas, revisión de eventos, métricas y retención programada |
| A10 SSRF | No se visitan URL/IOC de las muestras; destinos externos fijos; sin redirects de proveedores | Discovery OIDC solo de dominio confiable; controles egress de red |

## Cargas y disponibilidad

Límite durante streaming, un archivo por petición, 20 análisis por usuario por hora y 200 pendientes globales. La serialización de cuotas por usuario usa locks en PostgreSQL. SQLite no ofrece la misma concurrencia y debe mantenerse para desarrollo. Las cuotas de la aplicación no reemplazan protección de volumen, rate limits del proxy y límites de disco.

No hay un veredicto de «seguro». La reputación externa puede ser obsoleta o equivocada; el umbral de dos motores es una regla inicial documentada, no una garantía de detección. PDF/imágenes y contenedores cifrados o truncados no se declaran limpios por un fallo de parseo. Los originales se borran después del procesamiento; limpieza de huérfanos requiere ejecutar el comando de mantenimiento.

## IA

La IA no decide la clasificación, ejecuta herramientas ni consulta URL. En correos explica hallazgos técnicos y, solo si están activadas la política `AI_ALLOW_HEADER_UPLOAD` y la autorización de esa carga, recibe encabezados seleccionados del EML (con límites de tamaño). Estos pueden contener datos personales e instrucciones maliciosas: se transmiten como datos no confiables separados de las instrucciones del sistema. El cuerpo, los adjuntos y las firmas DKIM completas no se envían. Los encabezados detallados se conservan en la evidencia de administración y siguen la retención del análisis.

OpenAI y Gemini se llaman en endpoints HTTPS fijos, sin redirecciones; las claves se envían en encabezados HTTP, nunca en URLs. La respuesta del modelo se valida como JSON con campos y longitudes acotados, se filtran indicadores literales comunes del informe público y se escapa como texto al renderizar. La recomendación al usuario se deriva del veredicto técnico actual. Estas medidas no eliminan las alucinaciones ni toda forma de prompt injection o divulgación semántica: el informe se etiqueta como asistido por IA y no es evidencia de autenticidad. Los campos `Authentication-Results`, `Received-SPF` y `Received` de un EML no son una cadena de confianza; un PASS declarado nunca se trata como validación independiente. Revisa privacidad, residencia y retención del proveedor antes de habilitar encabezados externos.

## Pendientes antes de producción

Integración con SSO/API reales, hardening y aislamiento del sistema operativo, SAST/SCA/DAST y revisión independiente, pruebas de carga, monitoreo, restauración, retención programada y revisión de privacidad. Para detección profunda se recomienda añadir motores antivirus/sandbox administrados con sus propios límites de seguridad. La versión actual no implementa detonación, CDR ni un motor antivirus general.
