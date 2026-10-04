from __future__ import annotations

from idor_hunter.config import Config


def headers_similarity(
    a: dict[str, str],
    b: dict[str, str],
    config: Config | None = None,
) -> float:
    if config is None:
        config = Config()
    filt_a = {k.lower(): v for k, v in a.items() if k.lower() not in config.dynamic_headers}
    filt_b = {k.lower(): v for k, v in b.items() if k.lower() not in config.dynamic_headers}
    keys = set(filt_a) | set(filt_b)
    if not keys:
        return 1.0
    same = sum(1 for k in keys if filt_a.get(k) == filt_b.get(k))
    return same / len(keys)
