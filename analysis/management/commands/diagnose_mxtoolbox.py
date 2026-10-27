"""One public-domain SPF lookup; show only field names/types, never response values."""

import json
import re

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError

from analysis.mxtoolbox import request_lookup


def schema_fields(data):
    if not isinstance(data, dict):
        return []
    result = []
    for name, value in list(data.items())[:50]:
        if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,63}", name):
            continue
        item = {"name": name, "type": type(value).__name__}
        if isinstance(value, list) and value and isinstance(value[0], dict):
            item["item_fields"] = [
                {"name": child, "type": type(content).__name__}
                for child, content in list(value[0].items())[:30]
                if isinstance(child, str) and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,63}", child)
            ]
        result.append(item)
    return result


class Command(BaseCommand):
    help = "Consulta SPF de example.com (consume una consulta DNS) y muestra solo el esquema JSON."

    def handle(self, *args, **options):
        if not settings.MXTOOLBOX_ENABLED or not settings.MXTOOLBOX_API_KEY:
            raise CommandError(
                "Configura MXTOOLBOX_ENABLED=true y MXTOOLBOX_API_KEY en el entorno."
            )
        result = request_lookup("spf", "example.com", settings.MXTOOLBOX_API_KEY)
        payload = {"status": result["status"], "schema_fields": []}
        if result["status"] == "response_received":
            if result.get("response_truncated"):
                payload["status"] = "response_too_large_for_schema"
            else:
                try:
                    payload["schema_fields"] = schema_fields(json.loads(result["response_excerpt"]))
                except (TypeError, ValueError):
                    payload["status"] = "invalid_response"
        self.stdout.write(json.dumps(payload, ensure_ascii=False, indent=2))
