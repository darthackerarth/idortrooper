from __future__ import annotations

import re

NUMERIC_RE = re.compile(r"^\d+$")


def is_numeric_id(value: str) -> bool:
    return bool(NUMERIC_RE.match(value))


def is_short_numeric(value: str) -> bool:
    return value.isdigit() and len(value) <= 2
