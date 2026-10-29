# Filtraciones de cuentas

La cuarta pestaña, `/analisis/filtraciones/`, permite consultar exposición de un correo mediante Have I Been Pwned (HIBP), o abrir fuentes externas para una consulta manual. Requiere iniciar sesión en VIGIA. No pide contraseñas ni busca contraseñas filtradas.

## Fuentes de referencia

| Servicio | Alcance de referencia | Integración incluida |
| --- | --- | --- |
| [Have I Been Pwned](https://haveibeenpwned.com/) | Correos presentes en incidentes conocidos. [API v3 documentada](https://haveibeenpwned.com/API/v3); la búsqueda automática de cuentas requiere suscripción y clave propia. | Adaptador API opcional y enlace manual. |
| [HPI Identity Leak Checker](https://sec.hpi.de/ilc/) | Comprobación de exposición de una dirección de correo del Hasso Plattner Institute. | Enlace de consulta manual; sin envío automático desde VIGIA. |
| [F-Secure Identity Theft Checker](https://www.f-secure.com/en/identity-theft-checker) | Comprobación de exposición asociada a un correo. | Enlace de consulta manual; sin envío automático desde VIGIA. |
| [Malwarebytes Digital Footprint](https://www.malwarebytes.com/digital-footprint) | Revisión de exposición de datos vinculados a una cuenta. | Enlace de consulta manual; sin envío automático desde VIGIA. |

El usuario aportó además [Have I Been Ransom](https://haveibeenransom.com/) como referencia. No se conecta por API ni se presenta como una fuente consultada: no se ha confirmado su API ni su cobertura. Una búsqueda de organizaciones afectadas por ransomware no equivale a una búsqueda de cuentas personales filtradas; hay que comprobar qué cubre cada servicio.

Desde el entorno de desarrollo las páginas oficiales devolvieron un bloqueo del proxy (403) y la conexión directa no pudo resolver DNS. Por ello, **no se verificaron en vivo su disponibilidad, precios, condiciones ni cambios recientes**. Los enlaces son referencias conocidas; revisar documentación vigente, suscripción, permisos de uso y privacidad antes de activar un proveedor institucional. No hay scraping ni uso de endpoints internos no documentados. Las pruebas de integración usan respuestas simuladas y no una clave real del usuario.

## Activar la consulta automática

En `.env` del servidor web:

```dotenv
HIBP_ENABLED=true
HIBP_API_KEY=tu_clave_local_de_HIBP
```

Las claves de VirusTotal, Gemini, OpenAI o MXToolbox no sirven para HIBP. No se incluye ni se obtiene una suscripción. El worker de archivos no necesita esta clave y su entorno restringido no la recibe.

Después de actualizar el repositorio, ejecuta `bash scripts/setup.sh`, carga `.env` y reinicia el servidor web. Esta funcionalidad no añade una migración. Si no se habilita o falta la clave, la pestaña ofrece consultas manuales; no aparenta haber consultado un proveedor. Antes de su uso real, validar la clave y el plan con una cuenta cuya consulta esté autorizada.

## Consulta y datos

- Formulario POST con CSRF y SSO. Una casilla obligatoria confirma que la cuenta es propia o que existe autorización para consultarla, y explica que se enviará el correo completo a HIBP.
- GET no realiza consultas, incluso si alguien añade un correo en la URL de VIGIA. No se precompletan correos en los enlaces externos ni se cargan scripts o imágenes de proveedores. Abrir una fuente externa no le envía el correo introducido en VIGIA.
- Consulta HTTPS a `https://haveibeenpwned.com/api/v3/breachedaccount/{correo_codificado}`, con clave en `hibp-api-key`, User-Agent identificado, `truncateResponse=false` e `includeUnverified=false`. No sigue redirecciones y limita la respuesta a 1 MiB, 500 registros y textos acotados.
- Solo proyecta nombre del incidente, fecha y tipos de datos afectados. No muestra descripciones HTML del proveedor ni datos concretos filtrados. Los valores se escapan antes de mostrarlos.
- No guarda el correo consultado ni las respuestas en modelos, historial o sesión. Solo audita usuario, fecha y acción `breach_lookup`, sin dirección ni incidente. La página y el resultado tienen `Cache-Control: no-store`. El correo y la respuesta existen transitoriamente para servir la petición; el proveedor recibe el correo completo y tiene su propia política de conservación.
- Reserva cuota antes de llamar al proveedor: hasta 20 consultas por usuario por hora y 200 globales por hora. Las reservas se serializan en PostgreSQL; SQLite es solo para desarrollo. Los errores del proveedor también consumen un intento local. No reintenta automáticamente. Un POST recargado manualmente es una nueva consulta.
- HTTP 404 o una lista JSON vacía se interpretan como «Sin registros en la fuente consultada». Errores de autenticación, cuota, red, respuestas inválidas o timeout nunca se convierten en un resultado sin registros. Un resultado sin coincidencias no prueba ausencia de filtraciones. El proveedor puede excluir incidentes no verificados, sensibles, retirados u otros registros según sus reglas.
- Una coincidencia indica exposición registrada, posiblemente antigua. No demuestra acceso actual a la cuenta ni identifica responsables. Recomendar cambiar contraseñas reutilizadas, activar segundo factor y revisar accesos desde los sitios oficiales.

La consulta funciona en el proceso web (conexión 5 s, lectura 15 s), independiente del worker de archivos. La atribución visible a Have I Been Pwned identifica la única fuente de la consulta automática. Las fuentes manuales no se suman al resultado ni a un supuesto análisis de toda Internet.
