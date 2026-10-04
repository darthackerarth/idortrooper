from __future__ import annotations

from difflib import SequenceMatcher


def body_similarity(a: str, b: str) -> float:
    if not a and not b:
        return 1.0
    if not a or not b:
        return 0.0
    return SequenceMatcher(None, a, b).ratio()


def length_delta_ratio(a: str, b: str) -> float:
    if not a and not b:
        return 0.0
    m = max(len(a), len(b))
    if m == 0:
        return 0.0
    return abs(len(a) - len(b)) / m
