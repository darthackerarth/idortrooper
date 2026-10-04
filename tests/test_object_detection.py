from idor_hunter.config import Config
from idor_hunter.objects.detector import detect_objects
from idor_hunter.parser.raw_http import parse_raw_request


def _detect(raw: str):
    return detect_objects(parse_raw_request(raw), Config())


def test_numeric_id_in_path():
    raw = "GET /api/users/12345 HTTP/1.1\r\nHost: x\r\n\r\n"
    cands = _detect(raw)
    values = {c.value for c in cands}
    assert "12345" in values
    path_cands = [c for c in cands if c.location == "path"]
    assert path_cands and path_cands[0].object_type == "numeric_id"


def test_uuid_in_path():
    raw = (
        "GET /api/projects/550e8400-e29b-41d4-a716-446655440000 HTTP/1.1\r\n"
        "Host: x\r\n\r\n"
    )
    cands = _detect(raw)
    uuids = [c for c in cands if c.object_type == "uuid"]
    assert uuids and uuids[0].value == "550e8400-e29b-41d4-a716-446655440000"


def test_json_body_project_id():
    raw = (
        "POST /api/x HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\n\r\n"
        '{"projectId": 12345}'
    )
    cands = _detect(raw)
    json_cands = [c for c in cands if c.location == "json"]
    assert any(c.parameter_name == "projectId" and c.value == "12345" for c in json_cands)


def test_query_semantic_detection():
    raw = "GET /api/x?user_id=99001 HTTP/1.1\r\nHost: x\r\n\r\n"
    cands = _detect(raw)
    q = [c for c in cands if c.location == "query"]
    assert any(c.value == "99001" and c.parameter_name == "user_id" for c in q)


def test_hex_low_confidence():
    raw = "GET /api/x?h=5f4dcc3b5aa765d61d8327deb882cf99 HTTP/1.1\r\nHost: x\r\n\r\n"
    cands = _detect(raw)
    # Low-confidence hex without semantic name should NOT be a candidate
    assert not any(c.object_type == "hex_string" for c in cands)
