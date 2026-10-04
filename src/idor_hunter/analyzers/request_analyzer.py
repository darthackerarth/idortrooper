from __future__ import annotations

from idor_hunter.config import Config
from idor_hunter.models.object import ObjectCandidate
from idor_hunter.models.request import HttpRequest
from idor_hunter.objects.detector import detect_objects


def analyze_request(
    req: HttpRequest,
    config: Config | None = None,
) -> list[ObjectCandidate]:
    """Return all object candidates in a single request."""
    if config is None:
        config = Config()
    return detect_objects(req, config)
