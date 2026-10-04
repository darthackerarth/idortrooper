from __future__ import annotations

import json
from copy import deepcopy

from idor_hunter.config import Config
from idor_hunter.models.response import HttpResponse


def _normalize_json(value: object, dynamic_fields: set[str]) -> object:
    if isinstance(value, dict):
        return {
            k: _normalize_json(v, dynamic_fields)
            for k, v in value.items()
            if k.lower() not in dynamic_fields
        }
    if isinstance(value, list):
        return [_normalize_json(v, dynamic_fields) for v in value]
    return value


def normalize_response(
    resp: HttpResponse,
    config: Config | None = None,
) -> HttpResponse:
    """Strip dynamic headers and dynamic JSON fields.

    Conservative: it does NOT remove fields merely because they contain 'id'.
    """
    if config is None:
        config = Config()
    clone = deepcopy(resp)
    clone.headers = {
        k: v for k, v in clone.headers.items()
        if k.lower() not in config.dynamic_headers
    }

    ct = clone.content_type.lower()
    if clone.body and ("application/json" in ct or ct.endswith("+json")):
        try:
            data = json.loads(clone.body)
        except (json.JSONDecodeError, ValueError):
            return clone
        normalized = _normalize_json(data, config.dynamic_json_fields)
        try:
            clone.body = json.dumps(normalized, sort_keys=True, separators=(",", ":"))
        except (TypeError, ValueError):
            pass
    return clone
