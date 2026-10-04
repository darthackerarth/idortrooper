from __future__ import annotations

import re

SENSITIVE_HEADERS = {
    "authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "x-auth-token",
    "api-key",
    "proxy-authorization",
}

_REDACTED = "[REDACTED]"

_BEARER_RE = re.compile(r"(?i)\b(bearer|basic|token)\s+[A-Za-z0-9\-._~+/=]+")
_APIKEY_RE = re.compile(r"(?i)((?:api[-_]?key|secret|token)\s*[:=]\s*)[A-Za-z0-9\-._~+/=]+")
_JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+")


def redact_headers(headers: dict[str, str]) -> dict[str, str]:
    out: dict[str, str] = {}
    for k, v in headers.items():
        if k.lower() in SENSITIVE_HEADERS:
            out[k] = _REDACTED
        else:
            out[k] = v
    return out


def redact_text(text: str) -> str:
    if not text:
        return text
    text = _JWT_RE.sub(_REDACTED, text)
    text = _BEARER_RE.sub(lambda m: f"{m.group(1)} {_REDACTED}", text)
    text = _APIKEY_RE.sub(lambda m: f"{m.group(1)}{_REDACTED}", text)
    return text
