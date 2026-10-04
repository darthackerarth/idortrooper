from __future__ import annotations

import json
from typing import Any


def safe_load(text: str) -> Any | None:
    """Return the parsed JSON value or None if not parseable."""
    if not text or not text.strip():
        return None
    try:
        return json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return None


def walk_json(value: Any, path: str = "$") -> list[tuple[str, Any]]:
    """Yield (jsonpath, value) for every leaf key in a JSON structure."""
    results: list[tuple[str, Any]] = []
    if isinstance(value, dict):
        for k, v in value.items():
            child_path = f"{path}.{k}"
            if isinstance(v, (dict, list)):
                results.extend(walk_json(v, child_path))
            else:
                results.append((child_path, v))
    elif isinstance(value, list):
        for i, v in enumerate(value):
            child_path = f"{path}[{i}]"
            if isinstance(v, (dict, list)):
                results.extend(walk_json(v, child_path))
            else:
                results.append((child_path, v))
    return results
