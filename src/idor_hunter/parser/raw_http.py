from __future__ import annotations

from urllib.parse import parse_qs, urlparse

from idor_hunter.models.request import HttpRequest
from idor_hunter.models.response import HttpResponse


def _split_host_port(host_header: str) -> tuple[str, int | None]:
    if not host_header:
        return "", None
    if host_header.startswith("["):  # IPv6
        end = host_header.find("]")
        host = host_header[: end + 1]
        rest = host_header[end + 1:]
        if rest.startswith(":"):
            return host, int(rest[1:])
        return host, None
    if ":" in host_header:
        host, _, port_s = host_header.partition(":")
        try:
            return host, int(port_s)
        except ValueError:
            return host, None
    return host_header, None


def _normalize_newlines(text: str) -> str:
    return text.replace("\r\n", "\n").replace("\r", "\n")


def _split_head_body(text: str) -> tuple[str, str]:
    idx = text.find("\n\n")
    if idx == -1:
        return text, ""
    return text[:idx], text[idx + 2:]


def _parse_header_lines(lines: list[str]) -> dict[str, str]:
    headers: dict[str, str] = {}
    current: str | None = None
    for line in lines:
        if not line.strip():
            continue
        if line[0] in " \t" and current is not None:
            headers[current] = headers[current] + " " + line.strip()
            continue
        if ":" not in line:
            continue
        name, _, value = line.partition(":")
        name = name.strip()
        headers[name] = value.strip()
        current = name
    return headers


def _parse_cookies(header_value: str) -> dict[str, str]:
    cookies: dict[str, str] = {}
    if not header_value:
        return cookies
    for pair in header_value.split(";"):
        pair = pair.strip()
        if "=" in pair:
            k, _, v = pair.partition("=")
            cookies[k.strip()] = v.strip()
    return cookies


def _detect_body_type(content_type: str, body: str) -> str:
    if not body:
        return "empty"
    ct = content_type.lower()
    if "application/json" in ct or ct.endswith("+json"):
        return "json"
    if "application/x-www-form-urlencoded" in ct:
        return "form"
    return "text"


def parse_raw_request(raw: str) -> HttpRequest:
    """Parse a raw HTTP request text into an HttpRequest model."""
    text = _normalize_newlines(raw)
    head, body = _split_head_body(text)
    lines = head.split("\n")
    if not lines or not lines[0].strip():
        raise ValueError("Empty request")

    parts = lines[0].split()
    if len(parts) < 2:
        raise ValueError(f"Invalid request line: {lines[0]!r}")
    method = parts[0].upper()
    target = parts[1]
    http_version = parts[2] if len(parts) > 2 else "HTTP/1.1"

    headers = _parse_header_lines(lines[1:])

    scheme = "https"
    host = ""
    port: int | None = None

    if target.startswith(("http://", "https://")):
        u = urlparse(target)
        scheme = u.scheme or scheme
        host = u.hostname or ""
        port = u.port
        path = u.path or "/"
        query = u.query
    else:
        if "?" in target:
            path, _, query = target.partition("?")
        else:
            path, query = target, ""
        if not path:
            path = "/"

    host_header = next((v for k, v in headers.items() if k.lower() == "host"), "")
    if host_header and not host:
        host, host_port = _split_host_port(host_header)
        if host_port is not None:
            port = host_port
    if not host:
        host, host_port = _split_host_port(host_header)
        if host_port is not None:
            port = host_port

    query_params = parse_qs(query, keep_blank_values=True)

    cookie_header = next((v for k, v in headers.items() if k.lower() == "cookie"), "")
    cookies = _parse_cookies(cookie_header)

    content_type = next((v for k, v in headers.items() if k.lower() == "content-type"), "")
    body_type = _detect_body_type(content_type, body)

    return HttpRequest(
        method=method,
        scheme=scheme,
        host=host,
        port=port,
        path=path,
        query_params=query_params,
        headers=headers,
        cookies=cookies,
        body=body,
        body_type=body_type,
        raw=raw,
        http_version=http_version,
    )


def parse_raw_response(raw: str) -> HttpResponse:
    """Parse a raw HTTP response text into an HttpResponse model."""
    text = _normalize_newlines(raw)
    head, body = _split_head_body(text)
    lines = head.split("\n")
    if not lines or not lines[0].strip():
        raise ValueError("Empty response")

    status_line = lines[0].split()
    if len(status_line) < 2:
        raise ValueError(f"Invalid status line: {lines[0]!r}")
    http_version = status_line[0]
    try:
        status_code = int(status_line[1])
    except ValueError as exc:
        raise ValueError(f"Invalid status code: {status_line[1]!r}") from exc
    reason = " ".join(status_line[2:]) if len(status_line) > 2 else ""

    headers = _parse_header_lines(lines[1:])
    content_type = next((v for k, v in headers.items() if k.lower() == "content-type"), "")

    return HttpResponse(
        status_code=status_code,
        reason=reason,
        headers=headers,
        body=body,
        content_type=content_type,
        raw=raw,
        http_version=http_version,
    )
