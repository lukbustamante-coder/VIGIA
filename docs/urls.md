# Análisis de URL

La tercera pestaña acepta direcciones completas HTTP o HTTPS de hasta 2048 caracteres. VIGIA valida su estructura y consulta un reporte de reputación de VirusTotal; **nunca abre la URL objetivo, consulta su DNS, sigue redirecciones ni descarga la página**. No es un navegador ni una inspección del contenido web actual. La comunicación de la aplicación se dirige exclusivamente a endpoints HTTPS fijos de la API de VirusTotal, con TLS validado y redirecciones desactivadas.

Se rechazan esquemas distintos de HTTP/HTTPS, credenciales incrustadas, caracteres de control, dominios internos evidentes e IP literales privadas, locales o reservadas. Esta validación no demuestra que un dominio resuelva a una IP pública, porque no se consulta su DNS. El navegador muestra la URL como texto, nunca como un enlace para abrir la muestra.

## Configuración

Se usa la misma `VT_API_KEY` del módulo de archivos. Sin clave, cuota, un reporte válido o estadísticas de motores, el resultado es **No concluyente**. No se inventa una puntuación de motores.

Cada consulta requiere una casilla de autorización: el identificador base64 de la API comunica la URL completa a VirusTotal y no la anonimiza. La ruta, los parámetros y el fragmento pueden contener datos privados o tokens; no introduzcas enlaces confidenciales.

Si VirusTotal no conoce la dirección, no se solicita un análisis nuevo por defecto. Para permitirlo, agrega en `.env`:

```dotenv
VT_ALLOW_URL_SUBMISSION=true
```

Después carga de nuevo las variables y reinicia servidor y worker. El formulario mostrará otra casilla desmarcada: **Autorizar que VirusTotal analice la URL si no tiene un reporte**. Solo con política y autorización de esa carga se usa `POST /api/v3/urls`. En ese caso VirusTotal puede visitar la página y compartir resultados según sus condiciones. La autorización no permite envíos de EML, archivos o encabezados a otros servicios.

Si hay un reporte conocido se reutiliza. Si se solicita un análisis, el worker persiste su identificador y consulta su estado cada 30 segundos (60 ante cuota), con el mismo plazo de 30 minutos y máximo de 60 consultas de los archivos. No se vuelve a enviar la URL en cada consulta. Las cuotas de 20 análisis por usuario y hora y 200 pendientes son compartidas entre los tres módulos.

## Resultados y privacidad

Los usuarios reciben el veredicto y una explicación del alcance, con el historial de sus consultas identificado por el dominio que introdujeron. Los administradores pueden ver la URL completa como texto escapado, sus indicadores y las estadísticas del proveedor. El resultado público no expone la URL completa ni sus parámetros. Una detección maliciosa o alguna sospechosa produce **Sospechoso**; al menos dos detecciones maliciosas producen **Malicioso**. Un reporte con motores concluidos sin detecciones produce **Sin indicios detectados**, lo que no garantiza seguridad ni vigencia futura.

Las URLs se guardan en la base de datos con los resultados y siguen la retención de 30 días; no crean muestras en el directorio de archivos. No se pasan por argumentos de línea de comandos: el worker usa entrada estándar para evitar exponerlas en listados de procesos. Se auditan autorización e intento de consulta y, cuando corresponda, autorización e intento de análisis. Los intentos no prueban recepción o procesamiento por el proveedor y no son transacciones atómicas con la API.

Las URLs no se envían a OpenAI ni Gemini en este módulo. No se ha realizado una integración de navegación ni de IA con el contenido web. Las pruebas de VirusTotal usan respuestas simuladas; para comprobar la cuenta real usa una URL pública que tengas autorización para compartir.

## Categoría del sitio

El resultado incluye una sección independiente **Categoría del sitio** basada en el campo `categories` del objeto URL de VirusTotal. Se traducen etiquetas reconocidas a una taxonomía fija en español: contenido para adultos/pornografía, educación, noticias, redes sociales, compras, juegos, apuestas, tecnología, gobierno, salud, finanzas y otras categorías comunes. No se deduce el contenido por el nombre del dominio ni se solicita una clasificación a la IA.

Si los servicios reportan distintas categorías reconocidas, se muestran todas sin inventar una mayoría ni un porcentaje de confianza. Una etiqueta que no tiene equivalencia queda disponible solo en el detalle original para administradores; la vista de usuario indica que no hay una categoría reconocida cuando corresponde. Si el proveedor no ofrece categorías o no puede consultarse, se informa de su ausencia. La cobertura depende del sitio, del reporte y del acceso de la cuenta: no es una categorización universal ni una clasificación propia del contenido actual.

Esta información es independiente de las estadísticas de detección: una categoría de adultos no convierte por sí sola un sitio en malicioso y una categoría educacional no descarta que esté comprometido. Las etiquetas tampoco aplican bloqueos ni reglas de navegación.

Para URLs con reporte conocido, se obtiene la categoría en la misma consulta. Cuando VirusTotal termina un análisis solicitado, el worker hace una consulta adicional al objeto URL para recuperar las categorías, porque el objeto de análisis no las incluye. Esa lectura consume cuota de la misma cuenta y no vuelve a solicitar un escaneo; sus fallos no cambian el veredicto obtenido de los motores ni provocan reintentos automáticos. Los análisis anteriores no contienen estas etiquetas: vuelve a consultar la URL para guardarlas. No se requiere otra clave, activar IA ni migraciones adicionales para la categorización.

## Actualizar en Ubuntu

Detén el servidor y el worker antes de actualizar:

```bash
cd ~/VIGIA
git pull --ff-only origin main
bash scripts/setup.sh
```

El script aplica la migración de URLs y recoge los estilos. Carga `.env` en ambas terminales e inicia de nuevo el servidor y `scan_worker`. Abre `http://localhost:8000/analisis/urls/`. Si necesitas permitir el análisis de URLs desconocidas, activa la variable indicada antes de reiniciar ambos procesos.
