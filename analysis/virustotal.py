"""Optional sample submission and bounded polling against fixed VirusTotal endpoints."""

import re
import time

import requests

API = "https://www.virustotal.com/api/v3"
PENDING_STATUSES = {"queued", "in-progress", "quota_exceeded", "timeout", "unavailable"}
ANALYSIS_ID = re.compile(r"[A-Za-z0-9_=-]{1,512}\Z")
STAT_KEYS = (
    "malicious",
    "suspicious",
    "undetected",
    "harmless",
    "timeout",
    "confirmed-timeout",
    "failure",
    "type-unsupported",
)


def valid_analysis_id(value):
    return isinstance(value, str) and ANALYSIS_ID.fullmatch(value) is not None


def _error(response):
    errors = {
        401: "authentication_error",
        403: "access_denied",
        404: "analysis_not_found",
        429: "quota_exceeded",
    }
    if response.status_code in errors:
        return {"status": errors[response.status_code]}
    if 300 <= response.status_code < 400:
        return {"status": "unavailable"}
    response.raise_for_status()
    return None


def submit_sample(data, filename, key):
    """Called only after both operator enablement and per-submission consent."""
    result = {"upload_attempted": True}
    # Do not disclose the original filename to VirusTotal.
    extension = filename.rsplit(".", 1)[-1].lower()
    extension = extension if re.fullmatch(r"[a-z0-9]{1,12}", extension) else "bin"
    try:
        response = requests.post(
            f"{API}/files",
            headers={"x-apikey": key},
            files={"file": (f"sample.{extension}", data, "application/octet-stream")},
            timeout=(5, 30),
            allow_redirects=False,
        )
        error = _error(response)
        if error:
            return {**result, **error}
        # A 2xx response means a transfer occurred even if its JSON is unusable.
        result["sample_uploaded"] = True
        analysis_id = response.json()["data"]["id"]
        if not valid_analysis_id(analysis_id):
            raise ValueError("Invalid analysis ID")
        return {
            **result,
            "status": "queued",
            "analysis_id": analysis_id,
            "submitted_at": int(time.time()),
        }
    except requests.Timeout:
        return {**result, "status": "timeout"}
    except requests.exceptions.JSONDecodeError:
        return {**result, "status": "invalid_response"}
    except requests.RequestException:
        return {**result, "status": "unavailable"}
    except (TypeError, KeyError, ValueError):
        return {**result, "status": "invalid_response"}


def fetch_analysis(analysis_id, key):
    if not valid_analysis_id(analysis_id):
        return {"status": "invalid_response"}
    if not key:
        return {"status": "not_configured"}
    try:
        response = requests.get(
            f"{API}/analyses/{analysis_id}",
            headers={"x-apikey": key},
            timeout=(5, 15),
            allow_redirects=False,
        )
        error = _error(response)
        if error:
            return error
        attributes = response.json()["data"]["attributes"]
        status = attributes["status"]
        if status in {"queued", "in-progress"}:
            return {"status": status}
        if status != "completed":
            return {"status": "invalid_response"}
        stats = attributes["stats"]
        if not isinstance(stats, dict) or any(
            type(stats.get(name, 0)) is not int or not 0 <= stats.get(name, 0) <= 10000
            for name in STAT_KEYS
        ):
            return {"status": "invalid_response"}
        stats = {name: stats.get(name, 0) for name in STAT_KEYS}
        if sum(stats[name] for name in ("malicious", "suspicious", "undetected", "harmless")) == 0:
            return {"status": "no_results"}
        return {"status": "ok", "stats": stats, "last_analysis_date": attributes.get("date")}
    except requests.Timeout:
        return {"status": "timeout"}
    except requests.exceptions.JSONDecodeError:
        return {"status": "invalid_response"}
    except requests.RequestException:
        return {"status": "unavailable"}
    except (KeyError, TypeError, ValueError):
        return {"status": "invalid_response"}
