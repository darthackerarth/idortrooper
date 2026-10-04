from __future__ import annotations

from typing import Any


def _value_similarity(a: Any, b: Any) -> float:
    if isinstance(a, dict) and isinstance(b, dict):
        return json_similarity(a, b)
    if isinstance(a, list) and isinstance(b, list):
        if not a and not b:
            return 1.0
        n = max(len(a), len(b))
        m = min(len(a), len(b))
        if n == 0:
            return 1.0
        return sum(_value_similarity(a[i], b[i]) for i in range(m)) / n
    if type(a) is not type(b):
        return 1.0 if str(a) == str(b) else 0.0
    return 1.0 if a == b else 0.0


def json_similarity(a: Any, b: Any) -> float:
    """Structural + value similarity between two JSON values in [0, 1]."""
    if isinstance(a, dict) and isinstance(b, dict):
        keys_a, keys_b = set(a.keys()), set(b.keys())
        if not keys_a and not keys_b:
            return 1.0
        union = keys_a | keys_b
        if not union:
            return 1.0
        key_overlap = len(keys_a & keys_b) / len(union)
        common = keys_a & keys_b
        if not common:
            return 0.5 * key_overlap
        value_sim = sum(_value_similarity(a[k], b[k]) for k in common) / len(common)
        return 0.5 * key_overlap + 0.5 * value_sim

    if isinstance(a, list) and isinstance(b, list):
        return _value_similarity(a, b)

    if type(a) is not type(b):
        return 1.0 if str(a) == str(b) else 0.0
    return 1.0 if a == b else 0.0
