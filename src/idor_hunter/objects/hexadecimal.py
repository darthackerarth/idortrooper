from __future__ import annotations

import re

HEX_RE = re.compile(r"^[0-9a-fA-F]{16,}$")


def is_hex_string(value: str) -> bool:
    return bool(HEX_RE.match(value))
