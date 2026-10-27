"""URL reputation via fixed VirusTotal endpoints; never fetch the submitted address."""

import base64
import ipaddress
import os
import re
from urllib.parse import urlsplit, urlunsplit

import requests

from .url_categories import bounded_categories
from .virustotal import API, STAT_KEYS, _error, valid_analysis_id


def normalize_url(value):
    if not isinstance(value, str) or not 1 <= len(value) <= 2048:
        raise ValueError("La URL debe tener entre 1 y 2048 caracteres.")
    if any(char.isspace() or ord(char) < 32 or ord(char) == 127 for char in value) or "\\" in value:
        raise ValueError("La URL contiene espacios o caracteres no admitidos.")
    try:
        parts = urlsplit(value)
        if parts.scheme.lower() not in {"http", "https"} or not parts.hostname:
            raise ValueError("Introduce una URL completa con http:// o https://.")
        if parts.username is not None or parts.password is not None:
            raise ValueError("No se permiten URLs con usuario o contraseña incorporados.")
        host = parts.hostname.encode("idna").decode("ascii").lower().rstrip(".")
        if "%" in host:
            raise ValueError("No se permiten identificadores de zona en la dirección.")
        port = parts.port
        if port == 0:
            raise ValueError("Puerto no permitido.")
        try:
            address = ipaddress.ip_address(host)
        except ValueError:
            labels = host.split(".")
            if (
                len(host) > 253
                or len(labels) < 2
                or not re.fullmatch(r"[a-z][a-z0-9-]{1,62}", labels[-1])
                or any(
                    not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
                    for label in labels
                )
                or host.endswith((".localhost", ".local", ".internal", ".lan", ".home", ".onion"))
            ):
                raise ValueError(
                    "Introduce un dominio público válido; no se admiten nombres internos."
                )
        else:
            if not address.is_global or address.is_multicast or address.is_reserved:
                raise ValueError("No se permiten direcciones IP privadas, locales o reservadas.")
            if address.version == 6:
                host = f"[{host}]"
        authority = host + (f":{port}" if port is not None else "")
        normalized = urlunsplit(
            (parts.scheme.lower(), authority, parts.path or "/", parts.query, parts.fragment)
        )
        if len(normalized) > 2048:
            raise ValueError("La URL normalizada supera los 2048 caracteres.")
        return normalized
    except UnicodeError as error:
        raise ValueError("El dominio de la URL no es válido.") from error


def lookup_url(value, *, scan_consent=False):
    target = normalize_url(value)
    key = os.getenv("VT_API_KEY", "")
    if not key:
        return {"status": "not_configured"}
    identifier = base64.urlsafe_b64encode(target.encode()).decode().rstrip("=")
    attempted = False
    submitted = False
    category_data = {}
    try:
        response = requests.get(
            f"{API}/urls/{identifier}",
            headers={"x-apikey": key},
            timeout=(5, 15),
            allow_redirects=False,
        )
        if response.status_code == 404:
            if not (
                scan_consent and os.getenv("VT_ALLOW_URL_SUBMISSION", "false").lower() == "true"
            ):
                return {"status": "unknown_url"}
            attempted = True
            response = requests.post(
                f"{API}/urls",
                headers={"x-apikey": key},
                data={"url": target},
                timeout=(5, 20),
                allow_redirects=False,
            )
            error = _error(response)
            if error:
                return {**error, "url_scan_attempted": True}
            submitted = True
            analysis_id = response.json()["data"]["id"]
            if not valid_analysis_id(analysis_id):
                raise ValueError("Invalid analysis ID")
            return {
                "status": "queued",
                "analysis_id": analysis_id,
                "url_scan_attempted": True,
                "url_submitted": True,
            }
        error = _error(response)
        if error:
            return error
        attributes = response.json()["data"]["attributes"]
        category_data = {"categories": bounded_categories(attributes.get("categories"))}
        stats = attributes["last_analysis_stats"]
        if not isinstance(stats, dict) or any(
            type(stats.get(name, 0)) is not int or not 0 <= stats.get(name, 0) <= 10000
            for name in STAT_KEYS
        ):
            raise ValueError("Invalid statistics")
        stats = {name: stats.get(name, 0) for name in STAT_KEYS}
        if sum(stats[name] for name in ("malicious", "suspicious", "undetected", "harmless")) == 0:
            return {"status": "no_results", **category_data}
        return {
            "status": "ok",
            "stats": stats,
            "last_analysis_date": attributes.get("last_analysis_date"),
            **category_data,
        }
    except requests.Timeout:
        status = "timeout"
    except requests.exceptions.JSONDecodeError:
        status = "invalid_response"
    except requests.RequestException:
        status = "unavailable"
    except (KeyError, ValueError, TypeError, AttributeError):
        status = "invalid_response"
    return {
        "status": status,
        "url_scan_attempted": attempted,
        "url_submitted": submitted,
        **category_data,
    }


def analyze_url(value, *, scan_consent=False):
    from .scanner import Inspector

    target = normalize_url(value)
    inspector = Inspector()
    inspector.kind = "url"
    inspector.iocs["urls"].add(target)
    inspector.iocs["domains"].add(urlsplit(target).hostname)
    inspector.finding(
        "Consulta de reputación de URL; VIGIA no abre la página ni sigue redirecciones."
    )
    if urlsplit(target).scheme == "http":
        inspector.finding(
            "La URL utiliza HTTP sin cifrado de transporte; esto por sí solo no demuestra malicia."
        )
    provider = lookup_url(target, scan_consent=scan_consent)
    provider["query_attempted"] = bool(os.getenv("VT_API_KEY", ""))
    inspector.providers["virustotal"] = provider
    inspector.providers["ai"] = {"status": "not_applicable"}
    if provider["status"] == "ok":
        inspector.reputation_available = True
        inspector.malicious = provider["stats"]["malicious"] >= 2
        inspector.suspicious = (
            provider["stats"]["malicious"] == 1 or provider["stats"]["suspicious"] > 0
        )
    else:
        inspector.reputation_issue(
            provider["status"], "No hay un reporte de reputación completo para esta URL."
        )
        inspector.providers["virustotal"] = provider
    result = inspector.result()
    result["details"]["local_assessment"] = {
        "malicious": False,
        "suspicious": False,
        "incomplete": False,
    }
    return result
