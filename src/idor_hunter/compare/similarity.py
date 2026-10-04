from __future__ import annotations

import json
from typing import Any

from idor_hunter.compare.body import body_similarity, length_delta_ratio
from idor_hunter.compare.json import json_similarity
from idor_hunter.compare.status import status_similarity
from idor_hunter.config import Config
from idor_hunter.models.response import HttpResponse
from idor_hunter.normalize.response import normalize_response


def _try_json(text: str) -> Any | None:
    if not text or not text.strip():
        return None
    try:
        return json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return None


def compare_responses(
    a: HttpResponse,
    b: HttpResponse,
    config: Config | None = None,
) -> dict[str, Any]:
    if config is None:
        config = Config()

    na = normalize_response(a, config)
    nb = normalize_response(b, config)

    status_sim = status_similarity(a.status_code, b.status_code)
    body_sim = body_similarity(na.body, nb.body)
    len_delta = length_delta_ratio(na.body, nb.body)

    ja = _try_json(na.body)
    jb = _try_json(nb.body)
    json_sim: float | None = None
    if isinstance(ja, (dict, list)) and isinstance(jb, (dict, list)):
        json_sim = json_similarity(ja, jb)

    if json_sim is not None:
        overall = 0.55 * json_sim + 0.25 * body_sim + 0.10 * status_sim + 0.10 * (1.0 - len_delta)
    else:
        overall = 0.60 * body_sim + 0.25 * status_sim + 0.15 * (1.0 - len_delta)

    overall = max(0.0, min(1.0, overall))

    return {
        "status_a": a.status_code,
        "status_b": b.status_code,
        "status_similarity": round(status_sim, 4),
        "body_similarity": round(body_sim, 4),
        "json_similarity": round(json_sim, 4) if json_sim is not None else None,
        "length_delta": round(len_delta, 4),
        "similarity": round(overall, 4),
        "body_length_a": len(a.body),
        "body_length_b": len(b.body),
    }
