from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class HttpRequest:
    method: str
    scheme: str = "https"
    host: str = ""
    port: int | None = None
    path: str = "/"
    query_params: dict[str, list[str]] = field(default_factory=dict)
    headers: dict[str, str] = field(default_factory=dict)
    cookies: dict[str, str] = field(default_factory=dict)
    body: str = ""
    body_type: str = "empty"  # json | form | text | empty
    raw: str = ""
    http_version: str = "HTTP/1.1"

    def header(self, name: str) -> str | None:
        target = name.lower()
        for k, v in self.headers.items():
            if k.lower() == target:
                return v
        return None

    @property
    def query_string(self) -> str:
        parts: list[str] = []
        for k, values in self.query_params.items():
            for v in values:
                parts.append(f"{k}={v}")
        return "&".join(parts)

    @property
    def url(self) -> str:
        port_part = ""
        if self.port and not (
            (self.scheme == "https" and self.port == 443)
            or (self.scheme == "http" and self.port == 80)
        ):
            port_part = f":{self.port}"
        qs = f"?{self.query_string}" if self.query_string else ""
        return f"{self.scheme}://{self.host}{port_part}{self.path}{qs}"
