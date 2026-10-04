from __future__ import annotations

import json
from typing import Iterable

from idor_hunter.config import Config
from idor_hunter.models.object import ObjectCandidate
from idor_hunter.models.request import HttpRequest
from idor_hunter.objects.hexadecimal import is_hex_string
from idor_hunter.objects.numeric import is_numeric_id, is_short_numeric
from idor_hunter.objects.semantic import is_semantic_name
from idor_hunter.objects.uuid import is_uuid
from idor_hunter.parser.form_parser import parse_form_body


def _classify(
    value: str,
    *,
    location: str,
    parameter_name: str | None,
    context: str,
    config: Config,
    base_confidence: float,
) -> ObjectCandidate | None:
    """Return an ObjectCandidate if `value` looks like an identifier."""
    if not value:
        return None
    value_s = str(value)

    object_type: str | None = None
    confidence = base_confidence

    if is_uuid(value_s):
        object_type = "uuid"
        confidence = max(confidence, 0.95)
    elif is_numeric_id(value_s) and not is_short_numeric(value_s):
        object_type = "numeric_id"
        confidence = max(confidence, 0.85)
    elif is_numeric_id(value_s):
        object_type = "short_numeric"
        confidence = max(confidence, 0.5)
    elif is_hex_string(value_s):
        object_type = "hex_string"
        confidence = max(confidence, 0.45)
    elif len(value_s) >= 8 and any(c.isdigit() for c in value_s) and any(c.isalpha() for c in value_s):
        object_type = "alphanumeric_id"
        confidence = max(confidence, 0.55)

    if object_type is None:
        return None

    if parameter_name and is_semantic_name(parameter_name, config):
        confidence = min(1.0, confidence + 0.1)
    elif parameter_name is None and location in {"path", "json"}:
        # Bare values in path/json with no semantic hint keep their base confidence.
        pass

    # Low-confidence non-numeric in query/header is likely not an object.
    if (
        location in {"query", "header"}
        and object_type in {"hex_string", "alphanumeric_id"}
        and not is_semantic_name(parameter_name, config)
    ):
        return None

    return ObjectCandidate(
        value=value_s,
        location=location,  # type: ignore[arg-type]
        parameter_name=parameter_name,
        object_type=object_type,
        confidence=round(confidence, 4),
        context=context,
    )


def _detect_in_path(req: HttpRequest, config: Config) -> list[ObjectCandidate]:
    segments = req.path.split("/")
    results: list[ObjectCandidate] = []
    for idx, seg in enumerate(segments):
        if not seg:
            continue
        templated = "/".join(
            "{id}" if j == idx else s for j, s in enumerate(segments)
        )
        cand = _classify(
            seg,
            location="path",
            parameter_name=None,
            context=templated,
            config=config,
            base_confidence=0.9,
        )
        if cand:
            results.append(cand)
    return results


def _detect_in_query(req: HttpRequest, config: Config) -> list[ObjectCandidate]:
    results: list[ObjectCandidate] = []
    for name, values in req.query_params.items():
        for v in values:
            cand = _classify(
                v,
                location="query",
                parameter_name=name,
                context=f"?{name}={v}",
                config=config,
                base_confidence=0.7,
            )
            if cand:
                results.append(cand)
    return results


def _detect_in_headers(req: HttpRequest, config: Config) -> list[ObjectCandidate]:
    results: list[ObjectCandidate] = []
    skip_headers = {"cookie", "authorization", "host", "content-length", "user-agent"}
    for name, value in req.headers.items():
        if name.lower() in skip_headers:
            continue
        cand = _classify(
            value,
            location="header",
            parameter_name=name,
            context=f"{name}: {value}",
            config=config,
            base_confidence=0.5,
        )
        if cand:
            results.append(cand)
    return results


def _detect_in_cookies(req: HttpRequest, config: Config) -> list[ObjectCandidate]:
    """Cookies are inspected for identification only; values are never exposed
    in reports (see utils.redaction)."""
    results: list[ObjectCandidate] = []
    for name, value in req.cookies.items():
        cand = _classify(
            value,
            location="cookie",
            parameter_name=name,
            context=f"cookie:{name}",
            config=config,
            base_confidence=0.4,
        )
        if cand:
            results.append(cand)
    return results


def _walk_json(
    value: object,
    config: Config,
    context_prefix: str = "",
) -> Iterable[ObjectCandidate]:
    if isinstance(value, dict):
        for k, v in value.items():
            child_ctx = f"{context_prefix}.{k}" if context_prefix else k
            if isinstance(v, (dict, list)):
                yield from _walk_json(v, config, child_ctx)
            else:
                if v is None:
                    continue
                if isinstance(v, bool):
                    continue
                cand = _classify(
                    str(v),
                    location="json",
                    parameter_name=k,
                    context=child_ctx,
                    config=config,
                    base_confidence=0.7,
                )
                if cand:
                    yield cand
    elif isinstance(value, list):
        for i, item in enumerate(value):
            if isinstance(item, (dict, list)):
                yield from _walk_json(item, config, f"{context_prefix}[{i}]")


def _detect_in_json_body(req: HttpRequest, config: Config) -> list[ObjectCandidate]:
    if req.body_type != "json" or not req.body.strip():
        return []
    try:
        data = json.loads(req.body)
    except (json.JSONDecodeError, ValueError):
        return []
    return list(_walk_json(data, config))


def _detect_in_form_body(req: HttpRequest, config: Config) -> list[ObjectCandidate]:
    if req.body_type != "form" or not req.body.strip():
        return []
    parsed = parse_form_body(req.body)
    results: list[ObjectCandidate] = []
    for name, values in parsed.items():
        for v in values:
            cand = _classify(
                v,
                location="form",
                parameter_name=name,
                context=f"{name}={v}",
                config=config,
                base_confidence=0.65,
            )
            if cand:
                results.append(cand)
    return results


def detect_objects(req: HttpRequest, config: Config | None = None) -> list[ObjectCandidate]:
    """Detect all object identifier candidates in a request."""
    if config is None:
        config = Config()

    results: list[ObjectCandidate] = []
    results.extend(_detect_in_path(req, config))
    results.extend(_detect_in_query(req, config))
    results.extend(_detect_in_headers(req, config))
    results.extend(_detect_in_json_body(req, config))
    results.extend(_detect_in_form_body(req, config))
    results.extend(_detect_in_cookies(req, config))

    results.sort(key=lambda c: -c.confidence)
    return results
