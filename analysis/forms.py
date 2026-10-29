import struct
import zipfile
from email import policy
from email.parser import BytesHeaderParser

from django import forms
from django.conf import settings

from .url_inspection import normalize_url

FILE_EXTENSIONS = {
    "pdf",
    "zip",
    "doc",
    "docx",
    "xls",
    "xlsx",
    "ppt",
    "pptx",
    "odt",
    "ods",
    "odp",
    "txt",
    "csv",
    "rtf",
    "png",
    "jpg",
    "jpeg",
}


class URLAnalysisForm(forms.Form):
    url = forms.CharField(
        label="URL que quieres analizar",
        max_length=2048,
        widget=forms.URLInput(
            attrs={
                "placeholder": "https://sitio.example/ruta",
                "autocomplete": "off",
                "spellcheck": "false",
            }
        ),
        help_text="Solo HTTP o HTTPS. No incluyas contraseñas, tokens ni enlaces de acceso privado.",
    )
    vt_url_consent = forms.BooleanField(
        label="Autorizar la consulta de esta URL en VirusTotal",
        help_text="La consulta comunica la URL completa a VirusTotal, incluidos los parámetros. No envíes enlaces confidenciales.",
    )
    url_scan_consent = forms.BooleanField(
        required=False,
        label="Autorizar que VirusTotal analice la URL si no tiene un reporte",
        help_text="VirusTotal podrá visitar el sitio y compartir los resultados según sus condiciones. Esta autorización es independiente del envío de archivos y correos.",
    )

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if not settings.VT_ALLOW_URL_SUBMISSION:
            self.fields.pop("url_scan_consent")

    def clean_url(self):
        try:
            return normalize_url(self.cleaned_data["url"])
        except ValueError as error:
            raise forms.ValidationError(str(error)) from error

    def clean(self):
        data = super().clean()
        if self.data.get("url_scan_consent") and not settings.VT_ALLOW_URL_SUBMISSION:
            raise forms.ValidationError("El envío de URLs para análisis no está habilitado.")
        return data


class UploadForm(forms.Form):
    kind = forms.ChoiceField(label="Módulo", choices=[("eml", "Correo EML"), ("file", "Archivo")])
    file = forms.FileField(
        label="Archivo",
        widget=forms.ClearableFileInput(
            attrs={
                "class": "dropzone-input",
                "aria-describedby": "file-upload-help",
            }
        ),
    )
    vt_upload_consent = forms.BooleanField(
        required=False,
        label="Autorizar el envío de este archivo o correo a VirusTotal si no tiene reporte",
        help_text="Se compartirá su contenido completo con VirusTotal y podrá estar disponible para sus socios de seguridad. Marca esta opción solo si tienes autorización para compartirlo y no contiene información confidencial.",
    )
    ai_header_consent = forms.BooleanField(
        required=False,
        label="Autorizar el envío de los encabezados de este correo a la IA configurada",
        help_text="Puede incluir remitentes, destinatarios, asunto, servidores y direcciones IP. No se envían el cuerpo ni los adjuntos. Marca esta opción solo si tienes autorización para compartir esos datos con el proveedor externo.",
    )
    mxtoolbox_consent = forms.BooleanField(
        required=False,
        label="Autorizar consultas de configuración del correo en MXToolbox",
        help_text="Se compartirán solo los dominios de correo y, si está disponible, un selector de firma DKIM. No se envían direcciones completas, cuerpo ni adjuntos. Puede consumir hasta tres consultas DNS de la cuenta.",
    )
    email_resources_consent = forms.BooleanField(
        required=False,
        label="Autorizar el análisis individual de enlaces y adjuntos en VirusTotal",
        help_text="Se compartirán las URL completas, incluidos sus parámetros, y los adjuntos si el envío de muestras está habilitado. VirusTotal podrá visitar enlaces cuando el envío de URL esté habilitado. Puede compartir estos datos con sus socios. No autorices contenido confidencial ni enlaces de acceso privado. Consume consultas por cada elemento.",
    )

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if not settings.VT_ALLOW_SAMPLE_UPLOAD:
            self.fields.pop("vt_upload_consent")
        module = self.data.get("kind") if self.is_bound else self.initial.get("kind")
        if not settings.VT_ALLOW_EMAIL_RESOURCES or module != "eml":
            self.fields.pop("email_resources_consent")
        if not settings.AI_ALLOW_HEADER_UPLOAD or module != "eml":
            self.fields.pop("ai_header_consent")
        if not settings.MXTOOLBOX_ENABLED or module != "eml":
            self.fields.pop("mxtoolbox_consent")

    def clean(self):
        data = super().clean()
        if self.data.get("email_resources_consent") and (
            not settings.VT_ALLOW_EMAIL_RESOURCES or data.get("kind") != "eml"
        ):
            raise forms.ValidationError(
                "El análisis de enlaces y adjuntos no está habilitado para este módulo."
            )
        if self.data.get("mxtoolbox_consent") and (
            not settings.MXTOOLBOX_ENABLED or data.get("kind") != "eml"
        ):
            raise forms.ValidationError(
                "Las consultas a MXToolbox no están habilitadas para este módulo."
            )
        if self.data.get("ai_header_consent") and (
            not settings.AI_ALLOW_HEADER_UPLOAD or data.get("kind") != "eml"
        ):
            raise forms.ValidationError(
                "El envío de encabezados a la IA no está habilitado para este módulo."
            )
        if self.data.get("vt_upload_consent") and not settings.VT_ALLOW_SAMPLE_UPLOAD:
            raise forms.ValidationError("El envío de muestras a VirusTotal no está habilitado.")
        file, kind = data.get("file"), data.get("kind")
        if file and kind:
            extension = file.name.rsplit(".", 1)[-1].lower()
            allowed = {"eml"} if kind == "eml" else FILE_EXTENSIONS
            if extension not in allowed:
                raise forms.ValidationError("Formato no permitido para este módulo.")
            if file.size == 0 or file.size > 20 * 1024 * 1024:
                raise forms.ValidationError("El archivo debe tener entre 1 byte y 20 MB.")
            if not valid_signature(file, extension):
                raise forms.ValidationError("El contenido no coincide con el formato declarado.")
        return data


def valid_signature(file, extension):
    header = file.read(65536)
    file.seek(0)
    try:
        if extension == "eml":
            message = BytesHeaderParser(policy=policy.default).parsebytes(header)
            return any(message.get(key) for key in ("From", "To", "Subject", "Date", "Message-ID"))
        if extension == "pdf":
            return header.startswith(b"%PDF-")
        if extension in {"zip", "docx", "xlsx", "pptx", "odt", "ods", "odp"}:
            # Bound central directory bytes before parsing in the web process.
            file.seek(max(0, file.size - 65557))
            tail = file.read(65557)
            offset = tail.rfind(b"PK\x05\x06")
            if offset < 0 or len(tail) - offset < 22:
                return False
            disk, central_disk, disk_entries, count, directory_size = struct.unpack_from(
                "<HHHHI", tail, offset + 4
            )
            if (
                disk
                or central_disk
                or disk_entries != count
                or count > 100
                or directory_size > 65536
            ):
                return False
            file.seek(0)
            with zipfile.ZipFile(file) as archive:
                names = archive.namelist()
                if len(names) > 100:
                    return False
                expected = {"docx": "word/", "xlsx": "xl/", "pptx": "ppt/"}
                if extension in expected:
                    return "[Content_Types].xml" in names and any(
                        name.startswith(expected[extension]) for name in names
                    )
                if extension in {"odt", "ods", "odp"}:
                    return "mimetype" in names
                return True
        if extension in {"doc", "xls", "ppt"}:
            return header.startswith(bytes.fromhex("d0cf11e0a1b11ae1"))
        if extension == "rtf":
            return header.lstrip().startswith(b"{\\rtf")
        if extension == "png":
            return header.startswith(b"\x89PNG\r\n\x1a\n")
        if extension in {"jpg", "jpeg"}:
            return header.startswith(b"\xff\xd8\xff")
        if extension in {"txt", "csv"}:
            header.decode("utf-8-sig")
            return b"\x00" not in header and not header.startswith((b"MZ", b"#!"))
        return False
    except (ValueError, UnicodeError, zipfile.BadZipFile, OSError):
        return False
    finally:
        file.seek(0)
