"""Static inspection only: never executes, renders, extracts to disk, or visits IOCs."""

import hashlib
import io
import ipaddress
import json
import os
import re
import sys
import zipfile
from email import policy
from email.parser import BytesParser
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urlsplit

import olefile
import requests
from defusedxml import ElementTree

from .ai_reports import generate_header_report
from .email_headers import inspect_headers
from .pdf_inspection import inspect_pdf
from .virustotal import PENDING_STATUSES, fetch_analysis, submit_sample

MAX_BYTES = 20 * 1024 * 1024
MAX_ENTRIES = 100
URL_RE = re.compile(r'https?://[^\s<>"\x00-\x20]+', re.I)
DOMAIN_RE = re.compile(r"(?i)\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\b")
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
EICAR = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
OLE = bytes.fromhex("d0cf11e0a1b11ae1")
OFFICE = {"docx": "word/", "xlsx": "xl/", "pptx": "ppt/"}
ODF = {
    "odt": b"application/vnd.oasis.opendocument.text",
    "ods": b"application/vnd.oasis.opendocument.spreadsheet",
    "odp": b"application/vnd.oasis.opendocument.presentation",
}


class EmailHTMLInspector(HTMLParser):
    """Recognize active markup without rendering HTML or fetching resources."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.active = False

    def handle_starttag(self, tag, attrs):
        if tag in {"script", "iframe"} or any(
            name in {"onload", "onerror"} for name, _value in attrs
        ):
            self.active = True


class Inspector:
    def __init__(self):
        self.iocs = {
            "sha256": set(),
            "urls": set(),
            "domains": set(),
            "ipv4": set(),
            "emails": set(),
        }
        self.findings = []
        self.incomplete = False
        self.local_incomplete = False
        self.coverage_reasons = []
        self.reputation_available = False
        self.malicious = False
        self.suspicious = False
        self.remaining = MAX_BYTES
        self.entries = 0
        self.providers = {}
        self.kind = "file"
        self.email_headers = None
        self.ai_header_consent = False

    def finding(
        self, message, suspicious=False, incomplete=False, reason="local_inspection_limited"
    ):
        if len(self.findings) < 100:
            self.findings.append(message)
        self.suspicious |= suspicious
        self.incomplete |= incomplete
        self.local_incomplete |= incomplete
        if incomplete:
            self.coverage_reason("local", reason, message)

    def coverage_reason(self, source, code, message):
        reason = {"source": source, "code": code, "message": message}
        if reason not in self.coverage_reasons and len(self.coverage_reasons) < 100:
            self.coverage_reasons.append(reason)

    def reputation_issue(self, status, message):
        self.providers["virustotal"] = {"status": status}
        self.incomplete = True
        self.coverage_reason("virustotal", status, message)

    def indicators(self, data):
        # Work is bounded; IOC values are untrusted and always displayed as escaped text.
        text = data[: 2 * 1024 * 1024].decode("utf-8", errors="replace")
        for url in URL_RE.findall(text)[:100]:
            if len(self.iocs["urls"]) >= 100:
                break
            url = url[:2048].rstrip(".,;)")
            self.iocs["urls"].add(url)
            try:
                domain = urlsplit(url).hostname
                if domain:
                    self.iocs["domains"].add(domain[:253])
            except ValueError:
                pass
        self.iocs["domains"].update(DOMAIN_RE.findall(text)[:100])
        self.iocs["emails"].update(
            re.findall(r"[\w.+-]{1,64}@[\w.-]{1,253}\.[A-Za-z]{2,63}", text)[:100]
        )
        for value in IP_RE.findall(text)[:100]:
            try:
                self.iocs["ipv4"].add(str(ipaddress.IPv4Address(value)))
            except ValueError:
                pass

    def inspect(self, data, filename, kind="file", depth=0):
        if depth == 0:
            self.kind = kind
        self.iocs["sha256"].add(hashlib.sha256(data).hexdigest())
        if EICAR in data:
            self.malicious = True
            self.finding("Firma de prueba antivirus EICAR detectada.")
        if depth > 2:
            self.finding("Límite de anidamiento alcanzado.", incomplete=True)
            return
        ext = filename.rsplit(".", 1)[-1].lower()
        if kind == "eml":
            self.email(data, depth)
            return
        if data.startswith((b"MZ", b"\x7fELF", b"#!")):
            self.finding("Contenido ejecutable en un archivo no permitido.", suspicious=True)
            return
        if ext == "pdf":
            if not data.startswith(b"%PDF-") or b"%%EOF" not in data[-2048:]:
                self.finding("La estructura no corresponde a un PDF completo.", suspicious=True)
            if re.search(rb"/(JavaScript|JS|Launch|OpenAction|EmbeddedFile)\b", data):
                self.finding("PDF con acciones activas o archivos embebidos.", suspicious=True)
            inspect_pdf(self, data)
        elif ext in {"zip", *OFFICE, *ODF}:
            self.archive(data, ext, depth)
        elif ext in {"doc", "xls", "ppt"}:
            if not data.startswith(OLE):
                self.finding("La firma no coincide con Office binario.", suspicious=True)
            else:
                try:
                    with olefile.OleFileIO(io.BytesIO(data)) as doc:
                        names = ["/".join(name).lower() for name in doc.listdir()]
                        expected = {
                            "doc": {"worddocument"},
                            "xls": {"workbook", "book"},
                            "ppt": {"powerpoint document"},
                        }
                        if not any(name in expected[ext] for name in names):
                            self.finding(
                                "El tipo Office no coincide con la extensión.", suspicious=True
                            )
                        if any("vba" in name or "macros" in name for name in names):
                            self.finding("Documento con macros VBA.", suspicious=True)
                        if any("encryptedpackage" in name for name in names):
                            self.finding(
                                "Documento cifrado: contenido no inspeccionado.", incomplete=True
                            )
                except Exception:
                    self.finding("Contenedor Office inválido.", incomplete=True)
        elif ext == "rtf":
            if not data.lstrip().startswith(b"{\\rtf"):
                self.finding("Firma RTF inválida.", suspicious=True)
            if re.search(rb"\\(object|objdata|objupdate)\b", data, re.I):
                self.finding("RTF con objetos embebidos.", suspicious=True)
        elif ext in {"txt", "csv"}:
            try:
                decoded = data.decode("utf-8-sig")
                if "\x00" in decoded or re.search(r"<\s*(script|html|svg|iframe)\b", decoded, re.I):
                    self.finding("Contenido activo o binario disfrazado de texto.", suspicious=True)
                if ext == "csv" and re.search(r"(?:^|[\n,;])\s*[=+@]", decoded):
                    self.finding("CSV con posibles fórmulas activas.", suspicious=True)
            except UnicodeError:
                self.finding("Texto no UTF-8: inspección limitada.", incomplete=True)
        elif ext in {"png", "jpg", "jpeg"}:
            signature = b"\x89PNG\r\n\x1a\n" if ext == "png" else b"\xff\xd8\xff"
            if not data.startswith(signature):
                self.finding("La firma de imagen no coincide con la extensión.", suspicious=True)
            self.finding(
                "Imagen: se verifica firma, no se decodifica ni descarta un políglota.",
                incomplete=True,
            )
        else:
            self.finding("Contenido adjunto sin analizador permitido.", incomplete=True)
        self.indicators(data)

    def archive(self, data, ext, depth):
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as archive:
                infos = archive.infolist()
                names = {entry.filename for entry in infos}
                if ext in OFFICE and (
                    "[Content_Types].xml" not in names
                    or not any(name.startswith(OFFICE[ext]) for name in names)
                ):
                    self.finding("Estructura OOXML incompatible con su extensión.", suspicious=True)
                if ext in ODF and "mimetype" not in names:
                    self.finding("Estructura OpenDocument inválida.", suspicious=True)
                if len(infos) > MAX_ENTRIES:
                    self.finding("Demasiadas entradas en el contenedor.", incomplete=True)
                    return
                for entry in infos:
                    if entry.is_dir():
                        continue
                    self.entries += 1
                    normalized = entry.filename.replace("\\", "/")
                    if (
                        normalized.startswith("/")
                        or ".." in normalized.split("/")
                        or re.match(r"^[A-Za-z]:", normalized)
                    ):
                        self.finding("Ruta peligrosa dentro del contenedor.", suspicious=True)
                    if (entry.external_attr >> 16) & 0o170000 == 0o120000:
                        self.finding("Enlace simbólico en contenedor.", suspicious=True)
                    if entry.flag_bits & 1:
                        self.finding("Entrada cifrada no inspeccionada.", incomplete=True)
                        continue
                    if (
                        self.entries > MAX_ENTRIES
                        or entry.file_size > self.remaining
                        or entry.file_size / max(entry.compress_size, 1) > 100
                    ):
                        self.finding(
                            "Límite de expansión ZIP alcanzado.", incomplete=True, suspicious=True
                        )
                        return
                    with archive.open(entry) as stream:
                        content = stream.read(min(entry.file_size, self.remaining) + 1)
                    self.remaining -= len(content)
                    if len(content) != entry.file_size or self.remaining < 0:
                        self.finding("Tamaño ZIP inconsistente.", incomplete=True)
                        return
                    low = entry.filename.lower()
                    if low.endswith(
                        (
                            "vbaproject.bin",
                            ".exe",
                            ".dll",
                            ".js",
                            ".vbs",
                            ".ps1",
                            ".scr",
                            ".lnk",
                            ".bat",
                            ".cmd",
                            ".hta",
                        )
                    ):
                        self.finding(
                            "Macro o contenido ejecutable en el contenedor.", suspicious=True
                        )
                    if ext in OFFICE or ext in ODF:
                        if low == "mimetype" and ext in ODF and content != ODF[ext]:
                            self.finding("Tipo OpenDocument incompatible.", suspicious=True)
                        if low.endswith((".xml", ".rels")):
                            try:
                                tree = ElementTree.fromstring(content)
                                if any(
                                    node.attrib.get("TargetMode", "").lower() == "external"
                                    for node in tree.iter()
                                ):
                                    self.finding(
                                        "Documento con relaciones externas.", suspicious=True
                                    )
                            except Exception:
                                self.finding(
                                    "XML inválido o inseguro en documento.", incomplete=True
                                )
                        self.indicators(content)
                    else:
                        self.inspect(
                            content,
                            entry.filename,
                            "eml" if low.endswith(".eml") else "file",
                            depth + 1,
                        )
        except (zipfile.BadZipFile, RuntimeError, NotImplementedError, OSError, ValueError):
            self.finding("Contenedor ZIP inválido o no compatible.", incomplete=True)

    def email(self, data, depth):
        message = BytesParser(policy=policy.default).parsebytes(data)
        if depth == 0:
            self.email_headers = inspect_headers(message)
        if not any(message.get(name) for name in ("From", "To", "Subject", "Date", "Message-ID")):
            self.finding("No se reconoce una estructura EML válida.", suspicious=True)
        if message.defects:
            self.finding("Correo con estructura MIME defectuosa.", incomplete=True)
        self.indicators(str(message.items()).encode())
        from email.utils import parseaddr

        sender = parseaddr(str(message.get("From", "")))[1].lower()
        reply = parseaddr(str(message.get("Reply-To", "")))[1].lower()
        if sender and reply and sender.rsplit("@", 1)[-1] != reply.rsplit("@", 1)[-1]:
            self.finding(
                "From y Reply-To tienen dominios diferentes; este dato por sí solo no implica suplantación."
            )
        # Authentication-Results inside an uploaded EML is attacker-controlled.
        self.finding("SPF/DKIM/DMARC no verificados; los encabezados no prueban autenticidad.")
        parts = list(message.walk())
        if depth == 0 and len(parts) <= MAX_ENTRIES:
            self.email_headers["attachment_count"] = sum(
                bool(part.get_filename()) for part in parts if not part.is_multipart()
            )
        if len(parts) > MAX_ENTRIES:
            self.finding("Demasiadas partes MIME.", incomplete=True)
            return
        for part in parts:
            if part.is_multipart():
                continue
            self.entries += 1
            if self.entries > MAX_ENTRIES:
                self.finding("Límite global de partes alcanzado.", incomplete=True)
                return
            content = part.get_payload(decode=True) or b""
            if len(content) > self.remaining:
                self.finding("Límite de contenido MIME alcanzado.", incomplete=True)
                return
            self.remaining -= len(content)
            name = part.get_filename()
            if name:
                self.inspect(
                    content, name, "eml" if name.lower().endswith(".eml") else "file", depth + 1
                )
            elif part.get_content_type() in {"text/plain", "text/html"}:
                self.indicators(content)
                if part.get_content_type() == "text/html":
                    try:
                        parser = EmailHTMLInspector()
                        parser.feed(
                            content.decode(part.get_content_charset() or "utf-8", errors="replace")
                        )
                        parser.close()
                        if parser.active:
                            self.finding("Correo HTML con contenido activo.", suspicious=True)
                    except (LookupError, ValueError, AssertionError):
                        self.finding(
                            "HTML del correo no inspeccionado por completo.", incomplete=True
                        )
            else:
                self.finding("Parte MIME sin analizador disponible.", incomplete=True)

    def virus_total(self, digest, *, data=None, filename="sample.bin", upload_consent=False):
        key = os.getenv("VT_API_KEY", "")
        if not key:
            self.reputation_issue(
                "not_configured", "El worker no tiene una API key de VirusTotal configurada."
            )
            return
        try:
            response = requests.get(
                f"https://www.virustotal.com/api/v3/files/{digest}",
                headers={"x-apikey": key},
                timeout=(5, 15),
                allow_redirects=False,
            )
            if response.status_code == 404:
                if (
                    upload_consent
                    and os.getenv("VT_ALLOW_SAMPLE_UPLOAD", "false").lower() == "true"
                    and data is not None
                ):
                    provider = submit_sample(data, filename, key)
                    self.reputation_issue(
                        provider["status"],
                        "Se solicitó un análisis externo autorizado; consulta su estado en el reporte.",
                    )
                    self.providers["virustotal"] = provider
                    return
                self.reputation_issue(
                    "unknown_hash",
                    "VirusTotal no tiene un reporte para este hash; no se envió el archivo.",
                )
                return
            errors = {
                401: ("authentication_error", "VirusTotal rechazó la API key."),
                403: ("access_denied", "La cuenta no tiene acceso a esta consulta de VirusTotal."),
                429: ("quota_exceeded", "Se alcanzó la cuota de consultas de VirusTotal."),
            }
            if response.status_code in errors:
                self.reputation_issue(*errors[response.status_code])
                return
            response.raise_for_status()
            attributes = response.json()["data"]["attributes"]
            stats = attributes["last_analysis_stats"]
            keys = (
                "malicious",
                "suspicious",
                "undetected",
                "harmless",
                "timeout",
                "confirmed-timeout",
                "failure",
                "type-unsupported",
            )
            if not isinstance(stats, dict) or any(
                type(stats.get(name, 0)) is not int or not 0 <= stats.get(name, 0) <= 10000
                for name in keys
            ):
                raise ValueError("Invalid engine statistics")
            stats = {name: stats.get(name, 0) for name in keys}
            malicious = stats["malicious"]
            suspicious = stats["suspicious"]
            if (
                sum(stats[name] for name in ("malicious", "suspicious", "undetected", "harmless"))
                == 0
            ):
                self.reputation_issue(
                    "no_results", "VirusTotal no contiene resultados concluidos de motores."
                )
                return
            self.providers["virustotal"] = {
                "status": "ok",
                "stats": stats,
                "last_analysis_date": attributes.get("last_analysis_date"),
            }
            self.malicious |= malicious >= 2
            self.suspicious |= malicious == 1 or suspicious > 0
            self.reputation_available = True
        except requests.Timeout:
            self.reputation_issue("timeout", "La consulta a VirusTotal superó el tiempo de espera.")
        except requests.exceptions.JSONDecodeError:
            self.reputation_issue(
                "invalid_response", "VirusTotal devolvió un reporte sin estadísticas válidas."
            )
        except requests.RequestException:
            self.reputation_issue(
                "unavailable",
                "No fue posible obtener el reporte de VirusTotal por un fallo HTTP o de conexión.",
            )
        except (ValueError, TypeError, KeyError):
            self.reputation_issue(
                "invalid_response", "VirusTotal devolvió un reporte sin estadísticas válidas."
            )

    def ai(self):
        if self.kind == "eml":
            header_upload = (
                self.ai_header_consent
                and os.getenv("AI_ALLOW_HEADER_UPLOAD", "false").lower() == "true"
            )
            headers = self.email_headers or {}
            evidence = {
                "findings": self.findings,
                "verdict": "pending"
                if self.providers.get("virustotal", {}).get("status") in PENDING_STATUSES
                else self.result()["verdict"],
                "incomplete": self.incomplete,
                "authentication_independently_verified": False,
                "received_count": headers.get("received_count", 0),
                "declared_authentication": headers.get("declared_authentication", {}),
                "headers_truncated": headers.get("truncated", False),
            }
            if header_upload:
                evidence["untrusted_headers"] = headers.get("selected", {})
            self.providers["ai"] = {
                **generate_header_report(evidence),
                "data_scope": "headers" if header_upload else "technical_findings",
            }
            self.providers["ai"]["header_upload_attempted"] = (
                header_upload and self.providers["ai"].get("request_sent") is True
            )
            return
        if os.getenv("AI_PROVIDER", "openai").lower() != "openai":
            self.providers["ai"] = {"status": "not_applicable"}
            return
        key = os.getenv("AI_API_KEY", "")
        if not key:
            self.providers["ai"] = {"status": "not_configured"}
            return
        # Only fixed detector messages and provider status; no raw files, email body or IOC values.
        summary = {
            "findings": self.findings,
            "incomplete": self.incomplete,
            "local_malicious": self.malicious,
            "local_suspicious": self.suspicious,
        }
        try:
            response = requests.post(
                "https://api.openai.com/v1/chat/completions",
                headers={"Authorization": f"Bearer {key}"},
                json={
                    "model": os.getenv("AI_MODEL", "gpt-4.1-mini"),
                    "max_tokens": 350,
                    "messages": [
                        {
                            "role": "system",
                            "content": "Eres un asistente defensivo. Explica brevemente en español los hallazgos estáticos para un administrador. No declares un archivo seguro. No inventes evidencia. No cambies el veredicto.",
                        },
                        {"role": "user", "content": json.dumps(summary)},
                    ],
                },
                timeout=(5, 20),
                allow_redirects=False,
            )
            response.raise_for_status()
            explanation = response.json()["choices"][0]["message"]["content"]
            self.providers["ai"] = {"status": "ok", "explanation": str(explanation)[:4000]}
        except Exception:
            self.providers["ai"] = {"status": "unavailable"}

    def result(self):
        verdict = (
            "malicious"
            if self.malicious
            else "suspicious"
            if self.suspicious
            else "inconclusive"
            if self.incomplete
            else "no_indicators"
        )
        return {
            "verdict": verdict,
            "details": {
                "iocs": {key: sorted(values)[:100] for key, values in self.iocs.items()},
                "findings": self.findings,
                "incomplete": self.incomplete,
                "coverage": {
                    "local_complete": not self.local_incomplete,
                    "reputation_available": self.reputation_available,
                    "reasons": self.coverage_reasons,
                },
                "providers": self.providers,
                "module": self.kind,
                "email_headers": self.email_headers,
                "limitations": "Análisis estático sin ejecución ni sandbox antivirus. No demuestra inocuidad.",
            },
        }


def analyze(path, filename, kind, *, upload_consent=False, ai_header_consent=False):
    data = Path(path).read_bytes()
    if len(data) > MAX_BYTES:
        raise ValueError("Archivo demasiado grande")
    inspector = Inspector()
    inspector.ai_header_consent = ai_header_consent
    inspector.inspect(data, filename, kind)
    local = {
        "malicious": inspector.malicious,
        "suspicious": inspector.suspicious,
        "incomplete": inspector.local_incomplete,
    }
    # Reuse hash reports first. A sample upload requires both operator and user authorization.
    inspector.virus_total(
        hashlib.sha256(data).hexdigest(),
        data=data,
        filename=filename,
        upload_consent=upload_consent,
    )
    provider = inspector.providers.get("virustotal", {})
    if provider.get("analysis_id") and provider.get("status") in PENDING_STATUSES:
        if kind == "eml":
            inspector.ai()
        else:
            inspector.providers["ai"] = {"status": "deferred"}
    else:
        inspector.ai()
    result = inspector.result()
    result["details"]["file"] = {
        "sha256": hashlib.sha256(data).hexdigest(),
        "size_bytes": len(data),
    }
    result["details"]["local_assessment"] = local
    return result


def poll_virustotal(details):
    """Resume the original local assessment without rereading or resending the sample."""
    inspector = Inspector()
    inspector.kind = details.get("module", "file")
    inspector.email_headers = details.get("email_headers")
    local = details["local_assessment"]
    inspector.malicious = local["malicious"] is True
    inspector.suspicious = local["suspicious"] is True
    inspector.local_incomplete = local["incomplete"] is True
    inspector.incomplete = inspector.local_incomplete
    inspector.findings = details.get("findings", [])[:100]
    inspector.iocs = {
        name: set(details.get("iocs", {}).get(name, [])[:100]) for name in inspector.iocs
    }
    inspector.coverage_reasons = [
        r for r in details.get("coverage", {}).get("reasons", []) if r.get("source") == "local"
    ][:100]
    previous = details["providers"]["virustotal"]
    provider = {**previous, **fetch_analysis(previous["analysis_id"], os.getenv("VT_API_KEY", ""))}
    if provider["status"] == "ok":
        inspector.malicious |= provider["stats"]["malicious"] >= 2
        inspector.suspicious |= (
            provider["stats"]["malicious"] == 1 or provider["stats"]["suspicious"] > 0
        )
        inspector.reputation_available = True
        inspector.providers["virustotal"] = provider
        if inspector.kind == "eml":
            # Preserve the header explanation; no reupload or repeated AI charge while polling VT.
            inspector.providers["ai"] = details.get("providers", {}).get(
                "ai", {"status": "not_configured"}
            )
        else:
            inspector.ai()
    else:
        inspector.reputation_issue(
            provider["status"], "El análisis externo no ha entregado un reporte completo."
        )
        inspector.providers["virustotal"] = provider
        inspector.providers["ai"] = details.get("providers", {}).get("ai", {"status": "deferred"})
    result = inspector.result()
    result["details"]["file"] = details.get("file", {})
    result["details"]["local_assessment"] = local
    return result


if __name__ == "__main__":
    if sys.argv[1:] == ["--poll-vt"]:
        print(json.dumps(poll_virustotal(json.loads(sys.stdin.read(1024 * 1024)))))
    else:
        print(
            json.dumps(
                analyze(
                    *sys.argv[1:4],
                    upload_consent="--upload-to-vt" in sys.argv[4:],
                    ai_header_consent="--ai-headers" in sys.argv[4:],
                )
            )
        )
