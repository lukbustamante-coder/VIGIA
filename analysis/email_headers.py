"""Bounded observations from untrusted EML headers, without DNS or authenticity claims."""

import re

FIELDS = (
    "From",
    "To",
    "Reply-To",
    "Return-Path",
    "Date",
    "Message-ID",
    "Subject",
    "Received",
    "Received-SPF",
    "Authentication-Results",
    "ARC-Authentication-Results",
)


def inspect_headers(message):
    selected = {}
    truncated = False
    budget = 24000
    for name in FIELDS:
        values = message.get_all(name, [])
        truncated |= len(values) > 10
        selected[name] = []
        for value in values[:10]:
            text = " ".join(str(value).split())
            limit = min(2000, budget)
            truncated |= len(text) > limit
            selected[name].append(text[:limit])
            budget -= len(text[:limit])
    signatures = message.get_all("DKIM-Signature", [])
    selected["DKIM-Signature"] = []
    for signature in signatures[:10]:
        # Send signature metadata only, not the large signature/body hash itself.
        tags = dict(re.findall(r"(?:^|;)\s*([a-z]+)\s*=\s*([^;]*)", str(signature), re.I))
        selected["DKIM-Signature"].append(
            {name: tags.get(name, "")[:253] for name in ("d", "s", "a")}
        )
    declared = {name: [] for name in ("spf", "dkim", "dmarc")}
    for value in selected["Authentication-Results"] + selected["ARC-Authentication-Results"]:
        for method, result in re.findall(
            r"\b(spf|dkim|dmarc)\s*=\s*(pass|fail|softfail|neutral|none|temperror|permerror)\b",
            value,
            re.I,
        ):
            if result.lower() not in declared[method.lower()]:
                declared[method.lower()].append(result.lower())
    return {
        "selected": selected,
        "declared_authentication": declared,
        "received_count": len(message.get_all("Received", [])),
        "dkim_signature_count": len(signatures),
        "truncated": truncated or len(signatures) > 10,
        "independently_verified": False,
    }
