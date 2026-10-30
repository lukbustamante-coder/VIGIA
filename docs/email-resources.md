# VirusTotal para enlaces y adjuntos del correo

El informe incluye definiciones breves de IP, SPF, DKIM y DMARC. Sus comparaciones siguen basándose en los encabezados conservados, sin afirmar una verificación independiente de autenticidad.

Para consultar por separado los enlaces y adjuntos extraídos de nuevos EML, configura en el entorno de **web y worker**:

```dotenv
VT_API_KEY=tu_clave_local
VT_ALLOW_EMAIL_RESOURCES=true
VT_ALLOW_SAMPLE_UPLOAD=true
VT_ALLOW_URL_SUBMISSION=true
```

No compartas la clave en el repositorio. Las dos últimas opciones permiten enviar adjuntos o URL sin reporte; pueden dejarse en `false` para consultar únicamente reportes existentes. `VT_ALLOW_EMAIL_RESOURCES` está desactivado por defecto. Cada carga requiere marcar «Autorizar el análisis individual de enlaces y adjuntos en VirusTotal». Es una autorización distinta del envío del EML completo y de las consultas a MXToolbox. La IA utiliza la política institucional y no requiere una casilla por carga. Cambiar de archivo desmarca las autorizaciones.

Actualizar con `bash scripts/setup.sh` aplica la migración `0006`, que conserva los registros existentes con la autorización desactivada. Reinicia web y `scan_worker` cargando el mismo `.env`. Los análisis anteriores no se envían retroactivamente: hay que cargar de nuevo el correo y autorizarlo.

## Funcionamiento

- Consulta primero reportes por SHA-256 del adjunto o por identificador de la URL completa. Si faltan, usa `POST /files` o `POST /urls` cuando la correspondiente política global está habilitada. El nombre original del adjunto se sustituye por un nombre genérico al enviarlo.
- Persiste una cola de hasta 100 URL únicas y hasta 100 partes MIME; la extracción local tiene sus propios límites y no garantiza encontrar todos los enlaces. Se consideran adjuntos con nombre y partes MIME con disposición `attachment`; no se envían el cuerpo como adjunto ni archivos internos de un ZIP por separado. Se deduplican adjuntos por contenido y URL tras normalizarlas. Solo se aceptan URL HTTP(S) admitidas por el módulo de URL; se rechazan destinos literales privados o internos conocidos. VIGIA no resuelve ni visita estos destinos; VirusTotal puede hacerlo.
- Conserva temporalmente hasta 20 MiB de adjuntos decodificados bajo `<UUID>.resources/`, fuera de los estáticos, con directorio `0700` y archivos `0600` nombrados por hash. Los bytes no se guardan en JSON ni se pasan como argumentos de proceso. El EML original se elimina al terminar la inspección inicial, como antes. Los adjuntos pendientes se eliminan después de su consulta/envío, al terminar el trabajo o ante error/expiración. `purge_submissions` también retira directorios huérfanos.
- Procesa como máximo dos elementos por paso del worker, alternando consultas nuevas y análisis pendientes. Las consultas al EML original mantienen su ciclo existente. No mantiene un subproceso esperando minutos ni reenvía muestras mientras consulta un ID de análisis. Una respuesta 429 detiene el lote y retrasa el siguiente paso 60 segundos; no se repite automáticamente un POST sin ID confirmado, aunque haya fallado o agotado su tiempo.
- Los trabajos con esta autorización tienen un máximo de dos horas y 240 pasos. Cada subproceso tiene un máximo de 150 segundos, 30 segundos CPU y 512 MiB. La cuota de VirusTotal es compartida por toda la cuenta; muchos enlaces pueden tardar o quedar sin resultado. Deshabilitar `VT_ALLOW_EMAIL_RESOURCES` en un worker reiniciado cancela las consultas pendientes y elimina sus adjuntos.
- Una detección de al menos dos motores maliciosos en cualquier elemento produce «Malicioso»; un motor malicioso o alguno sospechoso produce «Sospechoso», según la política existente. Los hallazgos locales se conservan. Elementos omitidos, sin reporte o con error mantienen cobertura incompleta; nunca cuentan como elementos sin detecciones. Un error posterior conserva las detecciones obtenidas.
- Los usuarios ven cantidades revisadas y con detecciones, sin mostrar las URL completas ni nombres de adjuntos. Los administradores pueden consultar el resultado por elemento. No se convierten los enlaces en hipervínculos. `diagnose_analysis` muestra solo el resumen de cantidades. La auditoría registra autorización y pasos de la cola, sin contenido ni URL.

Las URL se comunican completas a VirusTotal, incluidos parámetros y fragmentos: pueden contener tokens o datos personales. El proveedor puede visitar las URL y compartir archivos o resultados con sus socios según las condiciones de la cuenta. No autorices contenido confidencial ni enlaces de acceso privado. SPF/DKIM/DMARC no se validan mediante estos análisis de reputación.
