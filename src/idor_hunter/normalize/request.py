from __future__ import annotations

from copy import deepcopy

from idor_hunter.config import Config
from idor_hunter.models.request import HttpRequest


def normalize_request(req: HttpRequest, config: Config | None = None) -> HttpRequest:
    """Return a shallow copy with dynamic headers removed.

    Conservative: it never strips fields that may be object identifiers.
    """
    if config is None:
        config = Config()
    clone = deepcopy(req)
    clone.headers = {
        k: v for k, v in clone.headers.items()
        if k.lower() not in config.dynamic_headers
    }
    return clone
