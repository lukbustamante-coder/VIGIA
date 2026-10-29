# Recomendaciones institucionales por módulo

Los textos de acción se seleccionan en `analysis/recommendations.py` a partir del módulo y del veredicto técnico actual. Aparecen una sola vez, junto al veredicto, con la acción principal en negrita. Los resultados ya guardados reciben los textos nuevos al abrirse, sin volver a analizar ni enviar el material.

| Módulo | Destino de ayuda | Ejemplo ante contenido malicioso |
| --- | --- | --- |
| URL | Soporte SISEI: `soporte.sisei@utem.cl` | No abrir la URL ni ingresar datos; solicitar ayuda si ya se abrió o se necesita orientación. |
| Archivos | Equipo de Ciberseguridad de UTEM | No abrir ni ejecutar el archivo; reportarlo para revisión. |
| Correos | Equipo de Ciberseguridad de UTEM o soporte SISEI | No abrir enlaces/adjuntos ni responder; reportar el mensaje. |

El contacto de soporte fue proporcionado explícitamente por el usuario. No se inventa una dirección para Ciberseguridad. Los enlaces `mailto:` contienen únicamente el destinatario, sin adjuntar archivos, incluir una URL posiblemente privada, copiar el cuerpo del correo o enviar un mensaje automáticamente.

Los estados sospechosos indican esperar revisión y reportar. Un resultado sin indicios recomienda comprobar origen o solicitudes sensibles y pedir ayuda ante dudas; no presenta el elemento como seguro ni pide reportar todos los casos sin detecciones. Un resultado no concluyente recomienda mantener el elemento sin abrir y solicitar revisión.

Mientras un análisis está en curso, se muestra el estado de espera y no una recomendación final basada en un veredicto provisional. Los fallos no producen una recomendación de confianza por un valor anterior sin indicios. En los informes de correo asistidos por IA, la recomendación pública se reemplaza por esta orientación institucional calculada con el veredicto actual, incluso si el texto del proveedor se generó en un análisis anterior. La evidencia y el contenido original del informe almacenado no se modifican.

No hay cambios de permisos, lógica de detección, llamadas a proveedores o esquema de base de datos.
