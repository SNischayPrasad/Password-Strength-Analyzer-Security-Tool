# REST API

Base URL (local): `http://127.0.0.1:5000`. All responses are JSON with `Cache-Control: no-store`.

## POST /api/analyze

Analyzes a password **in memory**. The password is not logged, not written to the database, not returned, and not included in error messages.

**Request**

```json
{
  "password": "<processed transiently>",
  "context": { "first_name": "DemoName", "birth_year": "1999", "organization": "Example Institute" },
  "record": false
}
```

| Field | Type | Required | Notes |
|---|---|---|---|
| `password` | string | yes | 1–256 characters |
| `context` | object | no | Optional demo values, each ≤ 100 characters, never stored |
| `record` | boolean | no | `true` stores **metadata only** for the dashboard. The real-time meter always sends `false`. |

**Response 200** (abridged)

```json
{
  "score": 25,
  "classification": "WEAK",
  "findings": [
    {"type": "keyboard_pattern", "severity": "high", "title": "Keyboard pattern",
     "description": "Found 1 keyboard walk (longest: 6 characters), like qwerty or asdf.",
     "count": 1, "max_length": 6}
  ],
  "suggestions": ["Avoid keyboard walks such as qwerty, asdf or 1qaz - they are among the first guesses tried.", "..."],
  "metrics": {
    "length": 11, "length_band": "SHORT", "character_type_count": 3,
    "unique_character_ratio": 0.909, "pool_size": 69,
    "theoretical_entropy_bits": 67.2, "adjusted_entropy_bits": 23.3,
    "guess_resistance": {"disclaimer": "Educational estimate only. ...", "scenarios": ["..."]},
    "score_breakdown": {"contributions": {"length": 19, "...": 0}, "penalties": ["..."], "caps": []},
    "pattern_map": [{"type": "keyboard_pattern", "start": 0, "end": 6}]
  },
  "checks": [{"label": "Keyboard pattern", "passed": false}],
  "policy": {"status": "POLICY FAIL", "passed": false, "rules": ["..."]},
  "recorded": false
}
```

`pattern_map` contains **positions only**. The UI draws the tiles from the text already in the user's own input field.

## POST /api/generate-password

```json
{ "length": 20, "uppercase": true, "lowercase": true, "digits": true, "symbols": true, "exclude_ambiguous": false }
```
→ `{"password": "...", "length": 20, "entropy_bits": 128.5, "note": "..."}`. Length must be 8–128. Uses `secrets`. Not stored.

## POST /api/generate-passphrase

```json
{ "word_count": 6, "separator": "-" }
```
→ `{"passphrase": "...", "word_count": 6, "entropy_bits": 53.5, "note": "EXAMPLE ONLY ..."}`

## GET /api/dashboard/stats
Aggregate counts: `total_analyses`, `average_score`, `classification_counts`, `score_distribution`, `length_distribution`, `weaknesses_per_analysis`, `weakness_types`.

## GET /api/analytics/weaknesses
`{"total_analyses": N, "weakness_types": [{"type": "dictionary_word", "count": 40, "percent_of_analyses": 26.7}, ...]}`

## GET /api/policy · GET /api/health
The active admin policy, and a liveness check.

## Validation, errors and status codes

| Code | When | Example body |
|---|---|---|
| 200 | Success | result |
| 400 | Missing/empty/non-string password, too long, bad context, bad options | `{"error": "Password is required."}` |
| 404 | Unknown endpoint / analytics disabled | `{"error": "Endpoint not found."}` |
| 405 | Wrong method (e.g. GET /api/analyze) | `{"error": "Method not allowed for this endpoint."}` |
| 413 | Body larger than 16 KB | `{"error": "Request body is too large."}` |
| 415 | Body is not JSON (e.g. form or query string) | `{"error": "Request body must be JSON ..."}` |
| 429 | Rate limit exceeded; includes `Retry-After` | `{"error": "Too many requests. ..."}` |
| 500 | Unexpected error: only the exception *type* is logged | `{"error": "Internal server error."}` |

## Security notes

- **Privacy:** the password lives only in the request's memory. Handlers never log request bodies, and a redaction filter masks `"password": ...` if someone logs it by mistake.
- **No URLs:** the password always travels in a POST body, and query strings are rejected (415). URLs end up in browser history, proxy logs and `Referer` headers.
- **Rate limiting:** per-IP sliding windows (240/min analyze, 60/min generate, configurable). Production should use a shared store or an API gateway.
- **HTTPS in production:** run behind a TLS-terminating reverse proxy (nginx, Caddy, a cloud load balancer) and enable HSTS there. Over plain HTTP, anyone on the network path could read the password.
- **Debug off:** `FLASK_DEBUG=false` by default, because the interactive debugger can display request data.
