# Informes de encabezados con OpenAI o Gemini

El módulo de correo extrae encabezados de transmisión, remitente, destinatario, asunto, autenticación declarada y metadatos DKIM. Los mantiene como evidencia no confiable, sin hacer consultas DNS ni verificar criptográficamente DKIM. Un `pass` en el EML se presenta como **PASS declarado**, no como validación de VIGIA. No se deduce que una dirección IP sea el equipo del remitente ni se consulta la reputación o propiedad de servidores mediante IA.

El propietario recibe un resumen de la ruta declarada, limitaciones de autenticación y una recomendación basada en el veredicto técnico. Los administradores conservan los encabezados e IOC detallados. El modelo no puede cambiar el veredicto, crear permisos, visitar enlaces ni ejecutar herramientas. Su texto puede contener errores y se identifica como explicación asistida por IA.

## Elegir proveedor

Edita `.env` localmente con `nano .env`; no compartas sus valores. Solo se consulta el proveedor seleccionado, no ambos. Se requiere una clave de API con acceso y cuota al modelo elegido; una suscripción a la aplicación de chat no implica acceso a su API. Los nombres de modelo son configurables y dependen de la disponibilidad de la cuenta.

Para OpenAI:

```dotenv
AI_PROVIDER=openai
AI_API_KEY=TU_CLAVE_CONFIGURADA_LOCALMENTE
AI_MODEL=gpt-4.1-mini
AI_ALLOW_HEADER_UPLOAD=true
```

`OPENAI_API_KEY` también se acepta para informes de correo y tiene prioridad sobre `AI_API_KEY`. Para archivos se mantiene el adaptador administrativo anterior, con `AI_API_KEY`.

Para Gemini:

```dotenv
AI_PROVIDER=gemini
GEMINI_API_KEY=TU_CLAVE_CONFIGURADA_LOCALMENTE
GEMINI_MODEL=gemini-2.5-flash
AI_ALLOW_HEADER_UPLOAD=true
```

Los valores `TU_CLAVE_CONFIGURADA_LOCALMENTE` son marcadores de documentación: sustitúyelos solo dentro de tu archivo local. `AI_MODEL` se aplica a OpenAI; `GEMINI_MODEL`, a Gemini. Para desactivar llamadas de IA usa `AI_PROVIDER=disabled`.

## Datos y autorización

Con la política desactivada o sin marcar la casilla, la IA solo recibe mensajes fijos de detectores, estados booleanos, cantidad de saltos y resultados declarados de SPF/DKIM/DMARC, sin direcciones ni valores originales de los encabezados.

Con `AI_ALLOW_HEADER_UPLOAD=true`, la pestaña de correo muestra una casilla desmarcada para autorizar el envío de encabezados de esa carga. Se rechaza una autorización enviada cuando la política está apagada o desde el módulo de archivos. El servidor envía únicamente los campos seleccionados por el analizador, con un presupuesto de 24 000 caracteres para los encabezados de texto y metadatos DKIM acotados. Puede incluir nombres, correos, asunto, identificadores, dominios e IP; revisa si puedes compartirlos con el proveedor. No se incluyen el cuerpo, los adjuntos, el hash del cuerpo ni la firma DKIM completa. La autorización de VirusTotal es independiente y, si se activa, sí puede enviar el EML completo a ese proveedor.

Los encabezados seleccionados permanecen en el reporte administrativo y se eliminan con la retención normal de resultados. No se escriben claves ni solicitudes/respuestas completas de las APIs en logs. Se auditan autorización e intento de envío. Un intento no demuestra que el proveedor haya recibido o procesado los datos.

## Actualizar y probar en Ubuntu / WSL

Detén el servidor y el worker antes de actualizar:

```bash
cd ~/VIGIA
git pull --ff-only origin main
bash scripts/setup.sh
nano .env
```

Carga las variables e inicia el servidor:

```bash
set -a
source .env
set +a
uv run python manage.py runserver 0.0.0.0:8000 --noreload
```

En otra terminal:

```bash
cd ~/VIGIA
set -a
source .env
set +a
uv run python manage.py scan_worker
```

Abre `http://localhost:8000/analisis/correos/`, carga un EML de prueba que tengas autorización para compartir y marca la casilla si quieres incluir sus encabezados. Los reportes anteriores no se regeneran. La explicación se muestra al completar el análisis; si VirusTotal necesita procesar la muestra, se conserva el informe de encabezados y no se repite la llamada a IA durante las consultas posteriores. La recomendación se actualiza según el veredicto técnico final.

Sin clave, ante límites de cuota, errores, bloqueos del proveedor o respuestas incompletas, el veredicto técnico se conserva y la explicación aparece como no disponible. No hay cambio automático de proveedor ni reintentos de IA. Consulta `uv run python manage.py diagnose_analysis --limit 5` después de cargar `.env`: muestra `ai_status`, sin revelar las claves ni los encabezados. `authentication_error`/`access_denied` indican rechazo de la API; `quota_exceeded`, cuota; `invalid_response`, salida no válida o incompleta.

Las pruebas automatizadas usan respuestas simuladas de ambas APIs: no sustituyen una prueba real con el modelo, cuenta y política de datos de tu institución.
