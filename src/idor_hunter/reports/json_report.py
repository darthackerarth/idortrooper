from __future__ import annotations

import json

from idor_hunter import __version__
from idor_hunter.models.finding import Finding


def render_json(finding: Finding, *, indent: int = 2) -> str:
    payload = {
        "tool": "idor-hunter",
        "version": __version__,
        "analysis": {
            "method": finding.method,
            "endpoint": finding.endpoint,
            "object": finding.object_candidate.to_dict() if finding.object_candidate else None,
            "comparison": finding.comparison,
            "ownership": finding.ownership,
            "score": finding.score,
            "classification": finding.classification,
            "evidence": finding.evidence,
            "recommendation": finding.recommendation,
        },
    }
    return json.dumps(payload, indent=indent, ensure_ascii=False)
