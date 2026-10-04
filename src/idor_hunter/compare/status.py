from __future__ import annotations


def status_similarity(a: int, b: int) -> float:
    if a == b:
        return 1.0
    if a // 100 == b // 100:
        return 0.7
    return 0.0


def is_2xx(code: int) -> bool:
    return 200 <= code < 300


def is_unauthorized(code: int) -> bool:
    return code == 401


def is_forbidden(code: int) -> bool:
    return code == 403


def is_not_found(code: int) -> bool:
    return code == 404


def is_error(code: int) -> bool:
    return code >= 400
