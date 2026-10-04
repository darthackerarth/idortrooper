from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class HttpResponse:
    status_code: int = 0
    reason: str = ""
    headers: dict[str, str] = field(default_factory=dict)
    body: str = ""
    content_type: str = ""
    raw: str = ""
    http_version: str = "HTTP/1.1"

    def header(self, name: str) -> str | None:
        target = name.lower()
        for k, v in self.headers.items():
            if k.lower() == target:
                return v
        return None

    @property
    def is_json(self) -> bool:
        ct = self.content_type.lower()
        return "application/json" in ct or ct.endswith("+json")
