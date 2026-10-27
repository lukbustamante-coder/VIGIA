# MXToolbox: consultas DNS complementarias

La documentación aportada confirma la base HTTPS `https://api.mxtoolbox.com/api/v1/`, la operación `GET Lookup/{Command}/?argument={argument}` y el encabezado `Authorization` con la API key sin prefijo Bearer. La cuenta mostrada dispone de 64 consultas DNS al día y 0 consultas de red. VIGIA solo permite los comandos DNS `spf`, `dmarc` y `dkim`: no activa HTTP, SMTP, ping, trace ni blacklist. Este adaptador no utiliza ni automatiza la página EmailHeaders.aspx; no se ha confirmado una operación API equivalente a su analizador de EML.

**Alcance actual:** conecta las consultas y conserva la respuesta JSON como evidencia administrativa. El esquema de los campos de respuesta todavía no está confirmado; por eso no se interpretan sus campos como PASS/FAIL, existencia de registros o autenticación superada. `response_received` significa únicamente que se recibió un objeto JSON en una respuesta HTTP satisfactoria. Incluso una respuesta que contenga errores de la consulta conserva ese significado y puede revisarse en administración. Las pruebas de transporte usan respuestas simuladas; falta validar la cuenta real en el equipo del usuario.

## Activar en Ubuntu

Detén servidor y worker, actualiza y aplica la migración:

```bash
cd ~/VIGIA
git pull --ff-only origin main
bash scripts/setup.sh
nano .env
```

Agrega la clave solo en tu archivo local, sin compartirla ni versionarla:

```dotenv
MXTOOLBOX_ENABLED=true
MXTOOLBOX_API_KEY=TU_CLAVE_CONFIGURADA_LOCALMENTE
```

Sustituye el marcador por tu clave real, sin `Bearer `. En cada terminal, carga nuevamente las variables antes de iniciar servidor o worker:

```bash
cd ~/VIGIA
set -a
source .env
set +a
```

Inicia el servidor con `uv run python manage.py runserver 0.0.0.0:8000 --noreload` y el worker en otra terminal con `uv run python manage.py scan_worker`.

La pestaña de correo mostrará una casilla independiente, desmarcada, para autorizar consultas a MXToolbox. Sin política y consentimiento no se hacen consultas ni se comparte la clave con el subproceso. La autorización no habilita envíos a VirusTotal, OpenAI o Gemini. Los análisis anteriores no se vuelven a consultar automáticamente.

## Datos enviados y límites

- SPF: dominio de `Return-Path`; si no hay uno válido, se usa el dominio de `From` como consulta orientativa y se deja registrado ese origen. No se comprueba la autorización de una IP concreta ni el remitente SMTP real.
- DMARC: dominio del `From` observado en el archivo.
- DKIM: dominio `d=` y selector `s=` de la primera firma con metadatos válidos, usando el argumento `dominio:selector`. No se envían la firma, el hash del cuerpo ni el cuerpo del correo, ni se validan criptográficamente.

Se validan los nombres de dominio y el selector; no se envían direcciones completas de personas, asuntos, nombres originales, cuerpo ni adjuntos. Son datos extraídos de un EML no confiable; no prueban quién envió el correo. Las consultas externas también pueden revelar que se está investigando un dominio concreto, por lo que requieren autorización.

Cada correo autorizado consume como máximo tres consultas DNS; la cuenta de 64 podría analizar aproximadamente 21 correos si todos necesitaran las tres consultas y no hubiera otro uso. Se detienen nuevas consultas del correo ante HTTP 401, 403 o 429. No se consultan Usage ni Monitor automáticamente y no hay reintentos de MXToolbox durante el seguimiento de VirusTotal. El scanner concede hasta 150 segundos de tiempo total a la fase inicial cuando MXToolbox está autorizado, frente a los 90 habituales; se mantienen los límites de CPU y memoria.

Los detalles de cada consulta se muestran solo a administradores como texto escapado, con un máximo de 20 000 caracteres por respuesta y ocultación de coincidencias literales de la API key. Los usuarios ven únicamente qué tipos de consultas recibieron información. Ni una respuesta recibida ni la configuración DNS actual cambian el veredicto de seguridad o prueban qué configuración existía al recibir el correo. Los resultados se eliminan con la retención normal de 30 días. Se auditan autorización e intento; no son una transacción atómica con el proveedor.

## Confirmar el esquema sin compartir claves ni resultados privados

Después de configurar y cargar `.env`, ejecuta:

```bash
uv run python manage.py diagnose_mxtoolbox
```

Consume una consulta DNS SPF de `example.com`. Solo imprime estado, nombres de campos y sus tipos; no muestra valores de respuesta, la clave ni encabezados de correos. Esa salida permite confirmar el esquema de la API y desarrollar después una interpretación automática precisa. Para ver el estado de los últimos análisis usa `uv run python manage.py diagnose_analysis --limit 5`, que tampoco muestra claves ni respuestas del proveedor.
