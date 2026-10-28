# Paleta institucional UTEM

La interfaz usa los valores RGB/HEX de la imagen del manual de identidad institucional compartida por el usuario. Referencia institucional: https://www.utem.cl/universidad/presentacion/identidad/.

| Color | HEX | Uso |
| --- | --- | --- |
| Azul institucional | `#004EAA` | Navegación, botones principales, enlaces y foco |
| Verde institucional | `#78BF26` | Identificador VIGIA, acentos de navegación y separadores |
| Blanco | `#FFFFFF` | Tarjetas, campos y texto sobre azul |
| Gris 70 % | `#706F6F` | Disponible para detalles secundarios |
| Gris 80 % | `#575756` | Texto secundario |
| Gris 90 % | `#3C3C3B` | Texto principal |
| Negro | `#000000` | Base neutral disponible |

Las variables se centralizan al inicio de `analysis/static/analysis/style.css`. Las superficies utilizan blanco y tintas claras derivadas del azul; la carga de archivos conserva una zona celeste diferenciada. El icono de la pestaña usa los mismos azul y verde. El esquema compartido se aplica a las páginas de ingreso, correo, archivos, URL, resultados, salida y errores propios de VIGIA.

El verde institucional se emplea como acento visual, evitando usarlo para texto pequeño sobre blanco. El contraste de azul sobre blanco es 7,86:1; el de texto principal sobre el fondo general es 10,37:1 y el de texto secundario sobre blanco es 7,23:1. Las combinaciones principales de texto y alertas comprobadas superan 4,5:1. Estas mediciones no sustituyen una auditoría integral de accesibilidad.

Los veredictos mantienen colores semánticos adicionales para expresar riesgo: rojo para malicioso, ámbar para sospechoso y verde oscuro para ausencia de indicios. Siempre se acompañan de texto o símbolos. Así se distingue el riesgo sin confundirlo con los acentos de marca. Los estados pendiente y no concluyente usan azul y gris.

La paleta no modifica validaciones, permisos, autorizaciones de terceros ni veredictos. Para desplegar cambios de estilo ejecuta `bash scripts/setup.sh` o recoge estáticos con `uv run python manage.py collectstatic --noinput`, reinicia el servidor y recarga el navegador sin caché.
