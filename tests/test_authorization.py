from idor_hunter.analyzers.authorization_analyzer import analyze_pair
from idor_hunter.config import Config
from idor_hunter.parser.raw_http import parse_raw_request, parse_raw_response
from idor_hunter.utils.redaction import redact_headers


def _req(host: str, path: str, auth: str):
    raw = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Authorization: Bearer {auth}\r\n"
        "\r\n"
    )
    return parse_raw_request(raw)


def _resp(status: int, body: str):
    raw = f"HTTP/1.1 {status} OK\r\nContent-Type: application/json\r\n\r\n{body}"
    return parse_raw_response(raw)


def test_strong_idor_candidate():
    ra = _req("example.com", "/api/projects/12345", "TOKEN_A")
    rb = _req("example.com", "/api/projects/12345", "TOKEN_B")
    ba = '{"id":12345,"ownerId":"ACCOUNT_A","name":"Project A","private":true}'
    bb = '{"id":12345,"ownerId":"ACCOUNT_A","name":"Project A","private":true}'
    finding = analyze_pair(ra, _resp(200, ba), rb, _resp(200, bb), Config())
    assert finding.score >= 85
    assert finding.classification == "critical-candidate"
    assert finding.ownership.get("detected") is True


def test_forbidden_reduces_score_to_informational():
    ra = _req("example.com", "/api/projects/12345", "TOKEN_A")
    rb = _req("example.com", "/api/projects/12345", "TOKEN_B")
    ba = '{"id":12345,"ownerId":"ACCOUNT_A","name":"Project A"}'
    bb = '{"error":"Forbidden"}'
    finding = analyze_pair(ra, _resp(200, ba), rb, _resp(403, bb), Config())
    assert finding.score < 30


def test_not_found_reduces_score():
    ra = _req("example.com", "/api/projects/12345", "TOKEN_A")
    rb = _req("example.com", "/api/projects/12345", "TOKEN_B")
    ba = '{"id":12345,"ownerId":"ACCOUNT_A"}'
    bb = '{"error":"Not found"}'
    finding = analyze_pair(ra, _resp(200, ba), rb, _resp(404, bb), Config())
    assert finding.score < 30


def test_public_object_not_flagged_as_critical():
    ra = _req("example.com", "/api/projects/1", "TOKEN_A")
    rb = _req("example.com", "/api/projects/1", "TOKEN_B")
    ba = '{"id":1,"name":"Public","public":true}'
    bb = '{"id":1,"name":"Public","public":true}'
    finding = analyze_pair(ra, _resp(200, ba), rb, _resp(200, bb), Config())
    # Not "critical": public hint reduces score.
    assert finding.score < 85


def test_secrets_never_exposed():
    headers = {
        "Authorization": "Bearer eyJabcdef.eyJabcdef.eyJabcdef",
        "Cookie": "session=abcdef",
        "X-API-Key": "supersecretvalue",
    }
    redacted = redact_headers(headers)
    assert redacted["Authorization"] == "[REDACTED]"
    assert redacted["Cookie"] == "[REDACTED]"
    assert redacted["X-API-Key"] == "[REDACTED]"
