from __future__ import annotations

import argparse
import sys
from pathlib import Path

from idor_hunter import __version__
from idor_hunter.analyzers.authorization_analyzer import analyze_pair
from idor_hunter.analyzers.request_analyzer import analyze_request
from idor_hunter.config import Config
from idor_hunter.models.finding import Finding
from idor_hunter.parser.raw_http import parse_raw_request, parse_raw_response
from idor_hunter.reports.console import render_console
from idor_hunter.reports.json_report import render_json
from idor_hunter.reports.text_report import render_text
from idor_hunter.utils.redaction import redact_headers, redact_text


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _cmd_parse(args: argparse.Namespace) -> int:
    raw = _read(Path(args.request))
    req = parse_raw_request(raw)
    print(f"Method:      {req.method}")
    print(f"Version:     {req.http_version}")
    print(f"Scheme:      {req.scheme}")
    print(f"Host:        {req.host}")
    print(f"Port:        {req.port}")
    print(f"Path:        {req.path}")
    print(f"Query:       {req.query_params}")
    print(f"Body type:   {req.body_type}")
    print("Headers:")
    for k, v in redact_headers(req.headers).items():
        print(f"  {k}: {v}")
    if req.cookies:
        print("Cookies:")
        for k in req.cookies:
            print(f"  {k}: [REDACTED]")
    if req.body:
        print("Body:")
        print(redact_text(req.body))
    return 0


def _cmd_detect(args: argparse.Namespace) -> int:
    raw = _read(Path(args.request))
    req = parse_raw_request(raw)
    cfg = Config()
    candidates = analyze_request(req, cfg)
    if not candidates:
        print("No object candidates detected.")
        return 0
    print(f"Detected {len(candidates)} object candidate(s):\n")
    for i, c in enumerate(candidates, 1):
        value_display = c.value
        if c.location == "cookie":
            value_display = "[REDACTED]"
        print(f"  [{i}] value={value_display} location={c.location}")
        if c.parameter_name:
            print(f"      parameter={c.parameter_name}")
        print(f"      type={c.object_type} confidence={c.confidence:.0%}")
        print(f"      context={c.context}")
        print()
    return 0


def _load_request_or_none(path: str | None):
    if not path:
        return None
    return parse_raw_request(_read(Path(path)))


def _load_response_or_none(path: str | None):
    if not path:
        return None
    return parse_raw_response(_read(Path(path)))


def _cmd_analyze(args: argparse.Namespace) -> int:
    req_a_path = args.request_a
    req_b_path = args.request_b
    if not req_a_path and len(args.positional) >= 1:
        req_a_path = args.positional[0]
    if not req_b_path and len(args.positional) >= 2:
        req_b_path = args.positional[1]
    if not req_a_path or not req_b_path:
        print("error: two request files required", file=sys.stderr)
        return 2

    try:
        req_a = parse_raw_request(_read(Path(req_a_path)))
        req_b = parse_raw_request(_read(Path(req_b_path)))
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    resp_a = _load_response_or_none(args.response_a)
    resp_b = _load_response_or_none(args.response_b)

    finding = analyze_pair(req_a, resp_a, req_b, resp_b, Config())

    if args.json:
        output = render_json(finding)
    else:
        output = render_console(finding)

    if args.output:
        Path(args.output).parent.mkdir(parents=True, exist_ok=True)
        Path(args.output).write_text(output, encoding="utf-8")
        print(f"Wrote report to {args.output}")
    else:
        print(output)
    return 0


def _cmd_report(args: argparse.Namespace) -> int:
    import json

    payload = json.loads(_read(Path(args.file)))
    analysis = payload.get("analysis", {})
    lines: list[str] = []
    lines.append(f"idor-hunter {payload.get('version', '')}")
    lines.append(f"Method:   {analysis.get('method')}")
    lines.append(f"Endpoint: {analysis.get('endpoint')}")
    obj = analysis.get("object") or {}
    if obj:
        lines.append(f"Object:   {obj.get('value')} ({obj.get('type')}, "
                     f"conf={obj.get('confidence')})")
    comp = analysis.get("comparison") or {}
    if comp:
        lines.append(f"A: {comp.get('status_a')}  B: {comp.get('status_b')}  "
                     f"sim={comp.get('similarity')}")
    own = analysis.get("ownership") or {}
    if own.get("detected"):
        lines.append(f"Ownership: {own.get('field')}")
    lines.append(f"Score: {analysis.get('score')}  "
                 f"Classification: {analysis.get('classification')}")
    ev = analysis.get("evidence") or []
    if ev:
        lines.append("Evidence:")
        for e in ev:
            lines.append(f"  - {e}")
    lines.append(f"Recommendation: {analysis.get('recommendation')}")
    print("\n".join(lines))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="idortrooper",
        description="Authorization Differential Analyzer for IDOR/BOLA candidates (offline V1).",
    )
    parser.add_argument("--version", action="version", version=f"idor-hunter {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    p_parse = sub.add_parser("parse", help="Parse a raw HTTP request file.")
    p_parse.add_argument("request", help="Path to a raw HTTP request file.")
    p_parse.set_defaults(func=_cmd_parse)

    p_detect = sub.add_parser("detect", help="Detect object candidates in a raw HTTP request.")
    p_detect.add_argument("request", help="Path to a raw HTTP request file.")
    p_detect.set_defaults(func=_cmd_detect)

    p_analyze = sub.add_parser(
        "analyze",
        help="Compare two requests (and optionally responses) for IDOR/BOLA candidates.",
    )
    p_analyze.add_argument("positional", nargs="*", help="Optional: request-a.txt request-b.txt")
    p_analyze.add_argument("--request-a", dest="request_a")
    p_analyze.add_argument("--response-a", dest="response_a")
    p_analyze.add_argument("--request-b", dest="request_b")
    p_analyze.add_argument("--response-b", dest="response_b")
    p_analyze.add_argument("--json", action="store_true", help="Emit JSON report.")
    p_analyze.add_argument("--output", "-o", help="Write report to a file.")
    p_analyze.set_defaults(func=_cmd_analyze)

    p_report = sub.add_parser("report", help="Render a JSON report produced by `analyze --json`.")
    p_report.add_argument("file", help="Path to a JSON report file.")
    p_report.set_defaults(func=_cmd_report)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args))
