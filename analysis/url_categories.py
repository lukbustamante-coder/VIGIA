"""Public taxonomy uses fixed labels; raw third-party labels stay in admin evidence."""

import re

CATEGORIES = {
    "Contenido para adultos / pornografía": {
        "adult",
        "adult content",
        "adult and pornography",
        "pornography",
        "porn",
        "sex",
        "nudity",
        "adult/mature content",
        "adult/mature content; pornography",
        "adult/mature content/pornography",
    },
    "Educación": {
        "education",
        "educational",
        "educational institutions",
        "education/reference",
        "education and reference",
        "reference",
    },
    "Noticias y medios": {"news", "news and media", "news/media", "news and media sites", "media"},
    "Redes sociales": {
        "social networking",
        "social networks",
        "social media",
        "social networking sites",
    },
    "Comercio y compras": {"shopping", "online shopping", "e-commerce", "auctions"},
    "Juegos": {"games", "gaming", "online games"},
    "Apuestas": {"gambling", "online gambling"},
    "Tecnología": {
        "information technology",
        "computers and internet",
        "computers/internet",
        "technology",
        "software/hardware",
        "software downloads",
    },
    "Gobierno e instituciones públicas": {
        "government",
        "government and legal organizations",
        "government/legal",
        "government/military",
    },
    "Salud": {"health", "health and medicine", "health/medicine"},
    "Finanzas": {"finance", "financial services", "finance and banking", "financial institutions"},
    "Empresas y servicios": {
        "business",
        "business and economy",
        "business/economy",
        "business services",
    },
    "Entretenimiento": {
        "entertainment",
        "streaming media",
        "streaming media and download",
        "music",
        "video",
    },
    "Buscadores y portales": {
        "search engines",
        "search engines and portals",
        "search engines/portals",
        "web portals",
    },
    "Correo web": {"webmail", "web-based email", "web based email"},
    "Viajes y turismo": {"travel", "travel and tourism"},
    "Phishing / suplantación": {"phishing", "phishing and other frauds", "fraud"},
    "Distribución de malware": {"malware", "malicious", "malicious websites", "malware sites"},
}


def bounded_categories(value):
    if not isinstance(value, dict):
        return {}
    result = {}
    for source, label in list(value.items())[:20]:
        if isinstance(source, str) and isinstance(label, str):
            source = " ".join(source.split())[:80]
            label = " ".join(label.split())[:200]
            if source and label:
                result[source] = label
    return result


def public_categories(value):
    raw = bounded_categories(value)
    labels = set()
    for value in raw.values():
        normalized = re.sub(r"\s+", " ", value.casefold()).strip()
        # Exact labels prevent, for example, classifying 'sex education' as pornography.
        candidates = {normalized, *(part.strip() for part in re.split(r"[;,|]", normalized))}
        for title, aliases in CATEGORIES.items():
            if candidates & aliases:
                labels.add(title)
    return {
        "status": "available" if labels else "unrecognized" if raw else "unavailable",
        "labels": sorted(labels),
    }
