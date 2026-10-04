from __future__ import annotations

from idor_hunter.config import Config


def is_semantic_name(name: str | None, config: Config) -> bool:
    if not name:
        return False
    return name.lower() in config.semantic_names
