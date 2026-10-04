from __future__ import annotations

import json
import re
from typing import Any

from idor_hunter.compare.similarity import compare_responses
from idor_hunter.config import Config
from idor_hunter.models.finding import Finding
from idor_hunter.models.object import ObjectCandidate
from idor_hunter.models.request import HttpRequest
from idor_hunter.models.response import HttpResponse
from idor_hunter.objects.detector import detect_objects
from idor_hunter.scoring.idor_score import ScoringContext, classify, compute_score

_ERROR_PATTERNS = [
    re.compile(r'"error"\s*:', re.IGNORECASE),
    re.compile(r'"errors"\s*:', re.IGNORECASE),
    re.compile(r'"message"\s*:\s*"[^"]*not\s+found', re.IGNORECASE),
    re.compile(r'"code"\s*:\s*"?not[_ ]?found', re.IGNORECASE),
]

_UNAUTHORIZED_PATTERNS = [
    re.compile(r"unauthori[sz]ed", re.IGNORECASE),
    re.compile(r"authentication\s+required", re.IGNORECASE),
    re.compile(r"invalid\s+token", re.IGNORECASE),
]

_FORBIDDEN_PATTERNS = [
    re.compile(r"forbidden", re.IGNORECASE),
    re.compile(r"access\s+denied", re.IGNORECASE),
    re.compile(r"permission\s+denied", re.IGNORECASE),
]


def _body_text(resp: HttpResponse | None) -> str:
    if resp is None:
        return ""
    return resp.body or ""


def _matches_any(patterns: list[re.Pattern[str]], text: str) -> bool:
    return any(p.search(text) for p in patterns)


def _try_json(text: str) -> Any | None:
    if not text or not text.strip():
        return None
    try:
        return json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return None


def _template_endpoint(req: HttpRequest, primary: ObjectCandidate | None) -> str:
    path = req.path
    if primary is None:
        return path
    if primary.location == "path":
        segments = path.split("/")
        for i, seg in enumerate(segments):
            if seg == primary.value:
                segments[i] = "{id}"
                break
        return "/".join(segments)
    if primary.location in {"query", "form"} and primary.parameter_name:
        return f"{path}?{primary.parameter_name}={{{primary.parameter_name}}}"
    if primary.location == "json":
        return f"{path} [json:{primary.parameter_name or 'value'}]"
    return path


def _detect_ownership(
    resp_a: HttpResponse | None,
    resp_b: HttpResponse | None,
    config: Config,
) -> dict[str, Any]:
    if resp_a is None or resp_b is None:
        return {"detected": False}
    da = _try_json(resp_a.body)
    db = _try_json(resp_b.body)
    if not isinstance(da, dict) or not isinstance(db, dict):
        return {"detected": False}

    fields_lower = {k.lower(): k for k in da.keys()}
    for lk, orig in fields_lower.items():
        if lk in config.ownership_fields:
            for kb in db.keys():
                if kb.lower() == lk:
                    if da[orig] == db[kb] and da[orig] not in (None, "", 0):
                        value = str(da[orig])
                        return {
                            "detected": True,
                            "field": orig,
                            "value_preview": value[:16] + ("…" if len(value) > 16 else ""),
                        }
    return {"detected": False}


def _contains_sensitive(resp: HttpResponse | None, config: Config) -> bool:
    if resp is None:
        return False
    data = _try_json(resp.body)
    if isinstance(data, dict):
        for k in data.keys():
            if k.lower() in config.sensitive_fields:
                return True
    else:
        low = resp.body.lower()
        for s in config.sensitive_fields:
            if s in low:
                return True
    return False


def _detect_visibility(
    resp: HttpResponse | None,
    config: Config,
) -> tuple[bool, bool]:
    """Return (is_private, is_public) hints."""
    if resp is None:
        return False, False
    data = _try_json(resp.body)
    if not isinstance(data, dict):
        return False, False
    is_private = False
    is_public = False
    for k, v in data.items():
        lk = k.lower()
        if lk in config.private_fields and v is True:
            is_private = True
        if lk in config.public_fields and v is True:
            is_public = True
        if lk in config.visibility_fields and isinstance(v, str):
            if v.lower() == "private":
                is_private = True
            elif v.lower() == "public":
                is_public = True
    return is_private, is_public


def _identifier_consistent(
    resp_a: HttpResponse | None,
    resp_b: HttpResponse | None,
    value: str,
) -> bool:
    if resp_a is None or resp_b is None:
        return False
    da = _try_json(resp_a.body)
    db = _try_json(resp_b.body)
    if not isinstance(da, dict) or not isinstance(db, dict):
        return False
    for k in da:
        if k.lower() in {"id", "uuid", "uid"}:
            return str(da[k]) == str(db.get(k)) == value
    return False


def _pick_primary_candidate(
    candidates_a: list[ObjectCandidate],
    candidates_b: list[ObjectCandidate],
) -> tuple[ObjectCandidate | None, bool]:
    """Return (primary_candidate, same_object_between_a_and_b)."""
    values_a = {c.value for c in candidates_a}
    values_b = {c.value for c in candidates_b}
    common = values_a & values_b

    ordered = sorted(candidates_a, key=lambda c: -c.confidence)
    for c in ordered:
        if c.value in common:
            return c, True
    if ordered:
        return ordered[0], False
    return None, False


def analyze_pair(
    req_a: HttpRequest,
    resp_a: HttpResponse | None,
    req_b: HttpRequest,
    resp_b: HttpResponse | None,
    config: Config | None = None,
) -> Finding:
    if config is None:
        config = Config()

    objs_a = detect_objects(req_a, config)
    objs_b = detect_objects(req_b, config)
    primary, same_object = _pick_primary_candidate(objs_a, objs_b)

    endpoint = _template_endpoint(req_a, primary)

    comparison: dict[str, Any] = {}
    ownership: dict[str, Any] = {"detected": False}
    is_private = is_public = False
    has_sensitive = False
    identifier_consistent = False

    if resp_a is not None and resp_b is not None:
        comparison = compare_responses(resp_a, resp_b, config)
        ownership = _detect_ownership(resp_a, resp_b, config)
        is_private, is_public = _detect_visibility(resp_b, config)
        has_sensitive = _contains_sensitive(resp_b, config)
        if primary is not None:
            identifier_consistent = _identifier_consistent(resp_a, resp_b, primary.value)

    text_a = _body_text(resp_a)
    text_b = _body_text(resp_b)
    is_error = _matches_any(_ERROR_PATTERNS, text_b) or (
        resp_b is not None and resp_b.status_code >= 400 and not _matches_any(_UNAUTHORIZED_PATTERNS, text_b) and not _matches_any(_FORBIDDEN_PATTERNS, text_b)
    )
    is_unauth = _matches_any(_UNAUTHORIZED_PATTERNS, text_b) or (resp_b is not None and resp_b.status_code == 401)
    is_forbidden = _matches_any(_FORBIDDEN_PATTERNS, text_b) or (resp_b is not None and resp_b.status_code == 403)

    # 404 handling: legitimate not found OR authorization hiding.
    if resp_b is not None and resp_b.status_code == 404:
        is_error = True
        is_public = False
        is_private = False

    ctx = ScoringContext(
        same_object=same_object,
        similarity=float(comparison.get("similarity", 0.0)),
        ownership_detected=bool(ownership.get("detected")),
        ownership_field=ownership.get("field"),
        status_b=resp_b.status_code if resp_b else 0,
        is_private=is_private,
        has_sensitive=has_sensitive,
        identifier_consistent=identifier_consistent,
        is_error=is_error,
        is_unauthorized=is_unauth,
        is_forbidden=is_forbidden,
        is_public=is_public,
    )

    score, evidence = compute_score(ctx)
    classification = classify(score)

    recommendation = (
        "Manually reproduce the request pair against the target and confirm that "
        "Account B is not authorized to access the referenced object. This tool "
        "provides heuristic evidence only and does not confirm a vulnerability."
    )

    return Finding(
        severity=classification,
        confidence=primary.confidence if primary else 0.0,
        endpoint=endpoint,
        method=req_a.method,
        object_candidate=primary,
        evidence=evidence,
        comparison=comparison,
        recommendation=recommendation,
        score=score,
        classification=classification,
        ownership=ownership,
    )
