# Filtraciones de cuentas: opción gratuita

La pestaña `/analisis/filtraciones/` utiliza **XposedOrNot por defecto**, sin suscripción ni clave. Requiere SSO y autorización por consulta. Solo permite consultar el correo verificado de la persona conectada, también para administradores. Los sitios externos conservan sus propios formularios y VIGIA no puede restringir lo que se introduzca allí. No solicita contraseñas.

## Fuentes

| Servicio | Consulta manual | API en VIGIA |
| --- | --- | --- |
| [XposedOrNot](https://xposedornot.com/) | Gratuita | API básica gratuita sin clave; proveedor predeterminado. |
| [Have I Been Pwned](https://haveibeenpwned.com/) | Búsqueda web gratuita de correos | Alternativa opcional de pago con clave propia. |
| [F-Secure Identity Theft Checker](https://www.f-secure.com/en/identity-theft-checker) | Comprobador público de exposición | Solo enlace manual; revisar condiciones actuales. |
| [Malwarebytes Digital Footprint](https://www.malwarebytes.com/digital-footprint) | Herramienta pública de revisión de exposición | Solo enlace manual; revisar condiciones actuales. |
| [Ciberlupa · Agencia Nacional de Ciberseguridad (ANCI, CHILE)](https://ciberlupa.anci.gob.cl/verificar/?type=rut) | Verificación externa por RUT | Solo enlace manual; no se solicita ni transmite el RUT desde VIGIA. |
| [CronUp Leaks](https://leaks.cronup.com/) | Fuente externa aportada por el usuario; consultar alcance y condiciones en su sitio | Solo enlace manual; API y cobertura no verificadas. |

CronUp Leaks se agregó como **Revisión manual**. El proxy del entorno bloqueó el acceso a su sitio, por lo que no se confirmó disponibilidad, cobertura, gratuidad ni una API oficial. Su enlace no incluye el correo consultado y no cuenta como resultado automático.

Have I Been Ransom fue aportado como referencia, pero no se ha confirmado su API ni su cobertura. Las bases de organizaciones afectadas por ransomware y las bases de cuentas personales filtradas tienen alcances diferentes.

## Fuente de la integración gratuita

Se verificó el 29 de octubre de 2026 la [documentación oficial publicada en el repositorio de XposedOrNot](https://github.com/XposedOrNot/XposedOrNot-Website/blob/master/api_doc.html), enlazada por el README oficial. La documentación confirma:

- `GET https://api.xposedornot.com/v1/check-email/{email}` sin clave para comprobaciones básicas.
- Respuesta positiva `{"breaches":[["Incidente", "Otro"]], "email":"...", "status":"success"}`.
- Respuesta sin coincidencias `{"Error":"Not found", "email":null}`. Se requiere ese formato, no un 404 genérico, para presentar ausencia de registros.
- Límites gratuitos por IP y endpoint: **2 solicitudes por segundo, 25 por hora y 100 por día**. El proveedor describe esta modalidad para uso personal y de bajo volumen; planes de mayor capacidad son de pago.

El sitio y el host API quedaron bloqueados por el proxy del entorno de desarrollo; el contenido oficial del repositorio sí pudo leerse. Se confirmó documentación y esquema, no la disponibilidad en vivo del endpoint. Las pruebas emplean respuestas simuladas. Revisar términos y privacidad antes de uso institucional; las condiciones pueden cambiar. No hay scraping, evasión de cuotas ni uso de endpoints internos.

## Configuración

Para la modalidad gratuita en el entorno del servidor web:

```dotenv
BREACH_PROVIDER=xposedornot
```

No se necesita `HIBP_API_KEY`. Si `BREACH_PROVIDER` no existe, se elige XposedOrNot salvo que una instalación anterior tenga `HIBP_ENABLED=true`; se conserva entonces HIBP por compatibilidad. Establece explícitamente `BREACH_PROVIDER=xposedornot` para seleccionar la opción gratuita.

Para deshabilitar las consultas automáticas y conservar los enlaces manuales:

```dotenv
BREACH_PROVIDER=disabled
```

La alternativa HIBP requiere una suscripción compatible:

```dotenv
BREACH_PROVIDER=hibp
HIBP_ENABLED=true
HIBP_API_KEY=tu_clave_local_de_HIBP
```

Actualiza el repositorio, ejecuta `bash scripts/setup.sh`, carga `.env` y reinicia el servidor web. No hay nueva migración. El worker de archivos no interviene ni recibe claves HIBP.

## Resultados y privacidad

- El formulario POST con CSRF exige autorizar el envío del correo de la sesión al proveedor identificado. El campo se completa desde SSO y está deshabilitado. En el servidor se utiliza únicamente la dirección de la sesión; enviar otra en un POST se rechaza antes de reservar cuota o llamar a la API. Nunca cambia automáticamente de proveedor después de un error.
- GET no consulta nada, aunque se agregue un correo en la URL de VIGIA. Los enlaces manuales no contienen direcciones precompletadas, usan `noopener noreferrer` y no cargan scripts ni imágenes remotas.
- Todas las consultas usan un host HTTPS fijo, correo codificado en la ruta, User-Agent identificado, conexión de 5 segundos y lectura de 15 segundos. No se siguen redirecciones. Respuesta máxima de 1 MiB, hasta 500 incidentes y textos acotados.
- XposedOrNot devuelve nombres de incidentes; esta modalidad no inventa fechas, tipos de datos ni detalles que no se recibieron. HIBP proyecta nombres, fechas y categorías cuando están disponibles. Nunca se muestran contraseñas, datos concretos filtrados o descripciones HTML del proveedor. Todo valor se escapa.
- El correo verificado del inicio de sesión se conserva como `oidc_email` en la sesión SSO, con su misma caducidad y eliminación al cerrar sesión. No se crean registros del correo consultado ni de los resultados en modelos o historial, ni se guardan los resultados en sesión. Solo se auditan usuario, fecha y acción (`breach_lookup_xon` o `breach_lookup`). El proveedor tiene su propia política de conservación. La respuesta tiene `Cache-Control: no-store`.
- Las cuotas se reservan antes del HTTP y se serializan en PostgreSQL; SQLite es para desarrollo. XposedOrNot: máximo 20 consultas por usuario/hora, 25 globales/hora, 100 globales en 24 horas y una reserva por segundo. Esta cadencia es más conservadora que su límite por segundo. La cuota real puede incluir otras aplicaciones con la misma IP pública.
- HIBP conserva el límite local de 20 consultas por usuario/hora y 200 globales/hora. Usa `truncateResponse=false` e `includeUnverified=false`. Fallos también consumen una reserva local; no hay reintentos automáticos. Recargar un POST manualmente es una nueva consulta.
- Los límites, errores HTTP, timeout o respuestas inválidas nunca se convierten en «Sin registros». No se evade un 429 cambiando de IP o de proveedor.
- No encontrar registros solo describe la base consultada. No garantiza ausencia de filtraciones ni seguridad actual de la cuenta. Una coincidencia puede ser antigua y no demuestra acceso actual ni identifica responsables. Se recomienda cambiar contraseñas reutilizadas, activar segundo factor y revisar accesos desde los sitios oficiales.

## Chequeo por fuente y Malwarebytes

La sección muestra una tarjeta por fuente, con texto, símbolo y color. Solo el proveedor API seleccionado recibe el correo después de autorizar la consulta. No se realizan nuevas consultas a otros proveedores por mostrar las tarjetas.

- Rojo: la fuente consultada devolvió registros de exposición.
- Verde: esa fuente devolvió un resultado sin registros, con la advertencia de cobertura limitada.
- Ámbar: límite de consultas, falta de respuesta o verificación externa requerida, según el texto de la tarjeta.
- Gris: revisión manual o resultado no disponible; nunca equivale a ausencia de filtraciones.
- Azul: la fuente automática está habilitada, pero todavía no se ha enviado la consulta.

El contador incluye solo fuentes con una respuesta final `found` o `no_records`. En la configuración gratuita actual puede mostrar **1 de 6 con resultado automático**; las otras cinco no se presentan como comprobadas. Errores y cuotas no cuentan como resultados completados. HIBP puede ser el proveedor automático si se configura la alternativa de pago, sin reutilizar el resultado de XposedOrNot en su tarjeta.

El usuario confirmó que solo tiene acceso al formulario web de Malwarebytes. Por tanto, su tarjeta indica **Verificación en Malwarebytes** y ofrece un enlace a su sitio y una guía: introducir allí el mismo correo, recibir el código y validarlo allí. Abrir el enlace no envía el correo, solicita códigos ni cambia la fila a «Sin registros».

No hay campos para ingresar el código en VIGIA ni una verificación simulada. El resultado externo no vuelve a la aplicación ni se almacena como comprobado. Vincular automáticamente solicitud, código y resultado al mismo correo queda pendiente de una API oficial documentada y accesible para ese flujo. No se utiliza el código para iniciar sesión en otro servicio, ni se consultan buzones o endpoints internos no documentados. Los resultados automáticos siguen siendo transitorios y sin historial de direcciones.

## Tarjetas y guías por fuente

Cada tarjeta conserva su estado y enlace externo visibles. Su nombre abre un `details` nativo con instrucciones propias del servicio, accesible con teclado y sin JavaScript. El antiguo bloque separado de Malwarebytes se integró en su tarjeta; la validación de códigos continúa exclusivamente en su sitio.

Ciberlupa se enlaza con `type=rut`. Es una revisión por RUT independiente de la búsqueda automática por correo. El entorno no pudo acceder a la página de ANCI para verificar su funcionamiento o API: no se simulan resultados ni se agregan campos de RUT o códigos en VIGIA.

Las imágenes se sirven localmente para evitar solicitudes del navegador a los proveedores al mostrar las tarjetas. Recursos:

- XposedOrNot: favicon del [repositorio oficial](https://raw.githubusercontent.com/XposedOrNot/XposedOrNot-Website/master/favicon.ico).
- Have I Been Pwned y Malwarebytes: marcas SVG de [Simple Icons](https://github.com/simple-icons/simple-icons), distribuidas bajo CC0; las marcas pertenecen a sus titulares.
- ANCI: adaptación PNG con transparencia a partir del logo aportado por el usuario; se muestra completo y sin recortes en la tarjeta de Ciberlupa.
- F-Secure y CronUp: siglas provisionales visibles, no logos oficiales. Se requieren sus archivos oficiales para sustituirlas.

## Correo de la sesión institucional

El callback OIDC obtiene `email` y `email_verified` exclusivamente de los claims del ID token ya validado. Solo acepta un correo sintácticamente válido, de hasta 254 caracteres, con `email_verified` booleano `true`. No usa `preferred_username`, parámetros GET/POST ni el correo almacenado en el usuario de Django como alternativa. Cada inicio de sesión reemplaza el valor anterior, incluso si el nuevo token no trae un correo utilizable.

Después de actualizar, las sesiones existentes deben cerrarse y volver a iniciarse para obtener este dato. Si falta el correo o no está verificado, el usuario puede seguir usando los otros módulos, pero la consulta automática de filtraciones queda bloqueada. El administrador de Keycloak debe revisar los mapeadores `email`/`email_verified` del ID token y verificar la dirección de la cuenta mediante el procedimiento institucional. No se deben marcar direcciones arbitrarias como verificadas para eludir esta comprobación.
