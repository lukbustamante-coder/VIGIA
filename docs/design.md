# Colores institucionales: UI kit UTEM

La referencia vigente son las dos capturas del **UI Kitv.1 UTEM**, nodo `3:423`, aportadas por el usuario: «Paleta Completa Institucional» y «Colores & Variables». Archivo: https://www.figma.com/design/PLfOYS7HrBQyHhSNlmsslL/UI-Kitv.1-UTEM-og?node-id=3-423. Los valores se transcribieron de esas imágenes; no se afirma haber accedido al archivo de Figma.

## Tokens activos

| Variable del kit | HEX | Aplicación |
| --- | --- | --- |
| accent-blue | `#004EAA` | Cabecera, botones, enlaces y foco |
| accent-green | `#78BF26` | Acentos, separadores y pestaña activa |
| text-light | `#001B36` | Texto principal y títulos principales |
| body-light | `#F5F5F5` | Fondo de página |
| card-light | `#FFFFFF` | Tarjetas, campos y pie |
| border-light | `#DDDDDD` | Bordes de tarjetas, tablas y separadores |
| Verde 800 | `#436A15` | Títulos secundarios y texto de resultados sin detecciones |
| Gris 600 | `#666666` | Texto secundario y ayudas |
| Azul 800 | `#003777` | Botones al pasar el cursor |
| Azul 100 | `#DDEDFF` | Encabezados de tablas y tarjeta celeste de carga |
| Azul 50 | `#F6FAFF` | Zona donde se sueltan archivos y superficies suaves |
| Verde 100 | `#F3FBE9` | Iconos con acento verde y fondos de estados positivos |
| Gris 500 | `#808080` | Borde de campos de formulario |

Se conserva toda la escala del kit en `analysis/static/analysis/style.css`:

- Azul, pasos 50 a 950: `#F6FAFF`, `#DDEDFF`, `#AAD1FF`, `#77B5FF`, `#449AFF`, `#117EFF`, `#0065DD`, `#004EAA`, `#003777`, `#002D5B`, `#001F44`.
- Verde, pasos 50 a 950: `#FFFFFF`, `#F3FBE9`, `#DAF2BF`, `#C2EA94`, `#AAE16A`, `#92D93F`, `#78BF26`, `#5D941E`, `#436A15`, `#283F0D`, `#1C2C09`.
- Grises, pasos 50 a 900: `#F2F2F2`, `#E6E6E6`, `#CCCCCC`, `#B3B3B3`, `#999999`, `#808080`, `#666666`, `#4D4D4D`, `#333333`, `#1A1A1A`.
- Opacidades: blanco al 26 % y 78 %; negro al 87 %, 54 %, 26 % y 12 %.

También se registran los valores oscuros suministrados: azul `#449AFF`, texto `#E1EAF3`, fondo `#000A14`, tarjeta `#001020`, borde `#002D5B`, y tooltip `#6B6B6B`. La interfaz actual sigue en tema claro; registrar estos tokens no añade un selector de tema ni activa un modo oscuro.

## Legibilidad y estados

El verde base tiene contraste 2,26:1 sobre blanco. Se utiliza su variante 800 del mismo kit para títulos secundarios y texto pequeño: 6,34:1 sobre blanco y 5,33:1 sobre azul 100. El gris 600 alcanza 5,74:1 sobre blanco y 4,82:1 sobre azul 100; el azul principal tiene 7,86:1 sobre blanco. Así se mantiene la identidad verde de los títulos sin perder legibilidad. Los valores son cálculos de contraste, no una auditoría integral de accesibilidad.

Las alertas mantienen rojo `#B42318` para exposiciones o malicia y ámbar `#8A5300` para sospechas, cuotas o verificaciones externas. Gris expresa revisión manual o resultado no disponible. Texto, símbolos y etiquetas acompañan los colores. Los nombres de fuentes y de incidentes permanecen en el color de texto principal para diferenciarlos del resultado.

Los estilos compartidos alcanzan portada, ingreso, cierre de sesión, errores, formularios de correo/archivos/URL, historial, resultados, tablas administrativas y filtraciones. El logo VIGIA sigue integrado en la cabecera y el favicon usa los mismos azul y verde base del kit.

## Actualización

Ejecuta `bash scripts/setup.sh` o `uv run python manage.py collectstatic --noinput`, reinicia el servidor y recarga el navegador. La hoja CSS utiliza la versión `utem-kit-1` para renovar la caché. Este cambio de presentación no requiere una migración.
