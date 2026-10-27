"""Optional DNS configuration lookups, never a message-authentication verdict."""

import ipaddress
import json
import os
import re
from email.utils import parseaddr

import requests

API = "https://api.mxtoolbox.com/api/v1"
COMMANDS = {"spf", "dmarc", "dkim"}
COMMAND_LABELS = {
    "spf": "Política de servidores de envío (SPF)",
    "dmarc": "Política contra la suplantación del dominio (DMARC)",
    "dkim": "Consulta de clave pública de firma (DKIM)",
}


def public_summary(provider):
    if not isinstance(provider, dict) or provider.get("status") in {
        None,
        "disabled",
        "not_authorized",
    }:
        return None
    checks = []
    for check in provider.get("checks", [])[:3]:
        command = check.get("command")
        if command in COMMAND_LABELS:
            checks.append(
                {
                    "name": COMMAND_LABELS[command],
                    "received": check.get("status") == "response_received",
                }
            )
    return {"checks": checks, "has_response": any(check["received"] for check in checks)}


def domain_name(value):
    if not isinstance(value, str):
        return None
    try:
        value = value.strip().rstrip(".").encode("idna").decode("ascii").lower()
        ipaddress.ip_address(value)
        return None
    except UnicodeError:
        return None
    except ValueError:
        pass
    labels = value.split(".")
    if (
        len(value) > 253
        or len(labels) < 2
        or not re.fullmatch(r"[a-z][a-z0-9-]{1,62}", labels[-1])
        or any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) for label in labels)
        or value.endswith((".local", ".localhost", ".internal", ".lan", ".onion"))
    ):
        return None
    return value


def lookup_plan(headers):
    selected = headers.get("selected", {})

    def address_domain(name):
        for value in selected.get(name, [])[:10]:
            address = parseaddr(value)[1]
            if "@" in address:
                domain = domain_name(address.rsplit("@", 1)[1])
                if domain:
                    return domain
        return None

    plan = []
    sender = address_domain("From")
    envelope = address_domain("Return-Path")
    if envelope or sender:
        plan.append(
            {
                "command": "spf",
                "argument": envelope or sender,
                "basis": "return_path" if envelope else "from_fallback",
            }
        )
    if sender:
        plan.append({"command": "dmarc", "argument": sender, "basis": "from"})
    for signature in selected.get("DKIM-Signature", [])[:10]:
        if not isinstance(signature, dict):
            continue
        domain = domain_name(signature.get("d"))
        selector = signature.get("s", "")
        if (
            domain
            and isinstance(selector, str)
            and 1 <= len(selector) <= 128
            and all(
                re.fullmatch(r"[A-Za-z0-9_](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?", label)
                for label in selector.split(".")
            )
        ):
            plan.append(
                {
                    "command": "dkim",
                    "argument": f"{domain}:{selector}",
                    "basis": "first_valid_signature",
                }
            )
            break
    return plan


def request_lookup(command, argument, key):
    if not isinstance(key, str) or not key:
        return {"status": "not_configured"}
    if command not in COMMANDS:
        return {"status": "invalid_request"}
    domain, separator, selector = argument.partition(":")
    if (
        not domain_name(domain)
        or (
            command == "dkim"
            and (not separator or not re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", selector))
        )
        or (command != "dkim" and separator)
    ):
        return {"status": "invalid_request"}
    try:
        response = requests.get(
            f"{API}/Lookup/{command}/",
            params={"argument": argument},
            headers={"Authorization": key},
            timeout=(3, 7),
            allow_redirects=False,
        )
        if response.status_code in {401, 403, 429}:
            return {
                "status": {
                    401: "authentication_error",
                    403: "access_denied",
                    429: "quota_exceeded",
                }[response.status_code],
                "request_attempted": True,
            }
        if 300 <= response.status_code < 400:
            return {"status": "unavailable", "request_attempted": True}
        response.raise_for_status()
        data = response.json()
        if not isinstance(data, dict):
            raise ValueError("Invalid response")
        # No interpretation of undocumented fields. HTTP success does not mean SPF/DKIM passed.
        encoded = json.dumps(data, ensure_ascii=False).replace(key, "[secreto omitido]")
        excerpt = encoded[:20000]
        return {
            "status": "response_received",
            "request_attempted": True,
            "response_excerpt": excerpt,
            "response_truncated": len(encoded) > 20000,
        }
    except requests.Timeout:
        return {"status": "timeout", "request_attempted": True}
    except requests.exceptions.JSONDecodeError:
        return {"status": "invalid_response", "request_attempted": True}
    except requests.RequestException:
        return {"status": "unavailable", "request_attempted": True}
    except (ValueError, TypeError):
        return {"status": "invalid_response", "request_attempted": True}


def check_configuration(headers, *, consent=False):
    if os.getenv("MXTOOLBOX_ENABLED", "false").lower() != "true":
        return {"status": "disabled", "checks": []}
    if not consent:
        return {"status": "not_authorized", "checks": []}
    key = os.getenv("MXTOOLBOX_API_KEY", "")
    if not key:
        return {"status": "not_configured", "checks": []}
    plan = lookup_plan(headers or {})
    if not plan:
        return {"status": "no_valid_domains", "checks": []}
    checks = []
    for query in plan[:3]:
        result = request_lookup(query["command"], query["argument"], key)
        checks.append({**query, **result})
        if result["status"] in {"authentication_error", "access_denied", "quota_exceeded"}:
            break
    return {
        "status": "response_received"
        if all(check["status"] == "response_received" for check in checks)
        else "partial_or_unavailable",
        "checks": checks,
        "planned_count": len(plan),
        "independently_verified": False,
    }
