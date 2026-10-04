import json

from idor_hunter.config import Config
from idor_hunter.normalize.response import normalize_response
from idor_hunter.parser.raw_http import parse_raw_response


def test_dynamic_fields_removed_from_json():
    raw = (
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n"
        '{"id": 1, "timestamp": "2024-01-01", "requestId": "abc", "name": "x"}'
    )
    resp = parse_raw_response(raw)
    normalized = normalize_response(resp, Config())
    data = json.loads(normalized.body)
    assert "timestamp" not in data
    assert "requestId" not in data
    assert data.get("id") == 1
    assert data.get("name") == "x"


def test_id_field_is_not_removed():
    raw = (
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n"
        '{"projectId": 12345}'
    )
    resp = parse_raw_response(raw)
    normalized = normalize_response(resp, Config())
    data = json.loads(normalized.body)
    assert data == {"projectId": 12345}
