from __future__ import annotations

from urllib.parse import parse_qs


def parse_form_body(body: str) -> dict[str, list[str]]:
    if not body:
        return {}
    return parse_qs(body, keep_blank_values=True)
