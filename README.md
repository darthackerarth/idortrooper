# idor-hunter (V1)

Authorization Differential Analyzer for IDOR/BOLA candidate detection.

> **Offline-first.** V1 does not send any HTTP traffic. It reads raw requests
> and responses you already captured.

## 1. What is IDOR / BOLA?

**IDOR (Insecure Direct Object Reference)** and **BOLA (Broken Object Level
Authorization)** are authorization flaws where an authenticated user can
access or manipulate objects belonging to another user by manipulating an
object identifier (numeric ID, UUID, slug, etc.).

Example: Account B replays Account A's request `GET /api/projects/12345` and
receives the same private JSON that Account A gets.

## 2. What this tool does

- Parses raw HTTP requests (and responses).
- Detects object identifier candidates in path, query, headers, JSON body,
  form body, and cookies.
- Normalizes dynamic fields (timestamps, request IDs, etc.).
- Compares two responses with structural JSON + textual similarity.
- Detects ownership fields (`ownerId`, `userId`, …).
- Produces a candidate score and a JSON / human report.

## 3. What this tool does NOT do

- No active exploitation, no crawling, no fuzzing, no brute force.
- Does not confirm vulnerabilities. It only produces **candidates** for manual
  verification.
- No Burp integration, no HAR, no replay (planned for V2).
- No SQLi, XSS, SSRF, RCE, credential attacks, WAF evasion.

## 4. Installation

```bash
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -e .
# or, without installing:
pip install -e .[dev]
