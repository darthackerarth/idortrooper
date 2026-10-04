# Examples

- `request_a.txt` — Account A requesting `/api/projects/12345`.
- `request_b.txt` — Account B requesting the same object.

Try:

```bash
idor-hunter parse examples/request_a.txt
idor-hunter detect examples/request_a.txt
idor-hunter analyze examples/request_a.txt examples/request_b.txt
