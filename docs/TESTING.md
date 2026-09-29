# Testing Strategy & Results

Run all tests from the project root:

```bash
python -m pytest -v
```

**Result on the reference machine (Windows 11, Python 3.13, Flask 3.1): 73 passed, 0 failed.**

All inputs are **synthetic demo values**. Test functions are named `test_T01_…` to `test_T30_…` so each row below maps to one automated test.

## Required scenarios (T01–T30)

| ID | Scenario | Input (synthetic) | Expected result | Actual result | Pass/Fail |
|---|---|---|---|---|---|
| T01 | Empty password | `""` | Score 0, VERY WEAK, no findings (API returns 400 "Password is required.") | 0, VERY WEAK, no findings; API 400 | PASS |
| T02 | One-character password | `x` | VERY WEAK, length band VERY_SHORT | 20, VERY WEAK | PASS |
| T03 | Short numeric | `4071` | VERY WEAK/WEAK, 1 character type | 20, VERY WEAK | PASS |
| T04 | Common password | `123456` | `common_password` finding, score ≤ 10 | 0, VERY WEAK, common + sequence | PASS |
| T05 | Long repeated | `aaaaaaaaaaaaaaaa` | Repetition found, WEAK despite 16 chars | 24, WEAK | PASS |
| T06 | Lowercase only | `vqkemzrd` | Lowercase only, 1 type | 1 type detected | PASS |
| T07 | Uppercase only | `VQKEMZRD` | Uppercase only, 1 type | 1 type detected | PASS |
| T08 | Numbers only | `80417362` | Digits only, pool 10 | pool 10 | PASS |
| T09 | Symbols only | `#%&*?~^` | Symbols only, 1 type | 1 type detected | PASS |
| T10 | Mixed characters | `vK7#mQ2!` | 4 types, 15 diversity points | 4 types, 15 points | PASS |
| T11 | Sequential numbers | `xx1234yy` | Ascending numeric run of 4 | detected, length 4 | PASS |
| T12 | Reverse numeric sequence | `9876` | Descending run | descending | PASS |
| T13 | Sequential letters | `abcd`, `DCBA` | Alphabetic asc/desc | both detected | PASS |
| T14 | Keyboard sequence | `qwerty`, `asdf`, `zxcv`, `qwerty123`, `1qaz` | Keyboard walk detected for each | all detected | PASS |
| T15 | Repeated characters | `AAAAAA123!` | Repeated characters ×6 | ×6 detected; score 25 WEAK | PASS |
| T16 | Repeated substring | `ababab`, `abcabcabc` | Unit length 2 / 3 | unit 2 (×3), unit 3 (×3) | PASS |
| T17 | Common word + number | `welcome123`, `hello1234`, `Password123!` | Structure `common_word_with_suffix`; Password123! WEAK/MODERATE | detected; Password123! = 38 WEAK | PASS |
| T18 | Word + year | `admin2026`, `qwerty2026!` | Year suffix + keyboard + date; WEAK | admin2026 = 28 WEAK; qwerty2026! = 25 WEAK | PASS |
| T19 | Personal name overlap | `Rahul@123` + first_name "Rahul" | `personal_info`; value not echoed | detected, field only; 24 WEAK | PASS |
| T20 | Birth-year overlap | `blue-kite-1999` + birth_year 1999 | `personal_info` | detected | PASS |
| T21 | Long passphrase-like | `walrus-trellis-cobalt-thimble-nectar` | Passphrase detected, no dictionary penalty, STRONG+ | 84, VERY STRONG | PASS |
| T22 | Unicode handling | `ñandú-Äpfel-日本語-ß` | non_ascii class, correct length, score in 0–100 | detected; 90 | PASS |
| T23 | Space handling | `violin tundra pebble socket` | Spaces class, policy PASS | 67 STRONG, POLICY PASS | PASS |
| T24 | Maximum accepted length | 256 × `k`, then 257 | 256 accepted, 257 rejected, no echo | as expected | PASS |
| T25 | Score boundaries | 0,20,21,40,41,60,61,80,81,100 | Correct band at each edge | all 10 correct | PASS |
| T26 | Suggestion generation | `qwerty2026!` | Mentions keyboard, year, MFA; never the password | as expected | PASS |
| T27 | Secure generation | 20-char generated | All 4 classes, 20 unique outputs, STRONG+ | as expected | PASS |
| T28 | Password not stored | `Zebra-Canary-4417-demo`, record=true | Not in raw DB bytes or any row | not found | PASS |
| T29 | Password not logged | same, plus an oversized input | Not in captured logs | not found | PASS |
| T30 | Analytics storage | schema | Only the 11 metadata columns; no password/hash column | exact match | PASS |

## Additional automated tests (43 more)

- **Engine:** length bands, leetspeak (`p@ssw0rd1` → common), entropy formula, "entropy is optimistic for Password123!" (theoretical > 70 bits, adjusted < 30), date detection, a random 20-char password scoring ≥ 61, policy separate from strength (`Welcome2026!` = WEAK yet POLICY PASS), and a check that the result never contains the password or context value.
- **API:** structure, 415 for non-JSON, 400 for empty/non-string/too-long input (no echo), 405 for GET, generator endpoints and validation, dashboard/weakness endpoints, policy endpoint, security headers, rate limiting (4th request → 429), pages served, bucket ordering.
- **Hashing demo:** salted (two hashes differ), `$argon2id$` format, correct/incorrect verification.

## Security testing

| Check | How it is verified | Why it matters |
|---|---|---|
| Password is not stored | `test_T28` scans the raw SQLite bytes (and any `-wal`/`-journal`) and every row | A stored password turns the tool into a target |
| Not in logs | `test_T29` captures all log output at DEBUG level | Logs are copied widely (SIEM, backups) and read by many people |
| Not in the database schema | `test_T30`, exact column set | No column means nothing can accidentally be saved |
| Not returned in API responses | `test_password_not_in_api_response` | Responses get cached, logged by proxies, and captured in screenshots |
| Not in error messages | `test_password_not_in_error_messages`, `…too_long…without_echo` | Error paths are where leaks usually happen |
| Not in URL parameters | Frontend uses POST + JSON (`test_password_never_sent_in_url…`); query-string requests rejected (`…query_string`) | URLs land in history, server logs, `Referer` |
| Uses a password field | `test_frontend_uses_password_field` (`type="password"`, `autocomplete="new-password"`) | Shoulder-surfing, and browsers don't cache/suggest it |
| No unnecessary persistence | `test_frontend_avoids_browser_storage…` (no local/session storage, no cookies, no console.log, no innerHTML); fields cleared on `pagehide` | Browser storage is readable by any script on the origin and survives sessions |
| localStorage / sessionStorage | Same test, plus a manual DevTools check (Application tab → both empty) | Same as above |
| Analytics contain only metadata | `test_T30` + `build_safe_record()` allow-list | Data minimization |
| Generator uses a CSPRNG | `test_generator_uses_secrets_not_random` | `random` is predictable |
| Accidental logging is masked | `test_redaction_filter_masks_accidental_logging` | Defence in depth |
| Debug mode off | `test_debug_mode_off_by_default` | The debugger can show request data |
| Security headers / no-store | `test_security_headers` | Stops caching of results and generated passwords; CSP limits XSS impact |

### Manual verification steps (for screenshots)

1. DevTools → **Network** → type a password → the `analyze` request is a **POST** and the URL has no query string.
2. DevTools → **Application** → Local Storage and Session Storage for `127.0.0.1:5000` are **empty**.
3. DevTools → **Console**: nothing logged.
4. Open `instance/analytics.db` in *DB Browser for SQLite* and show that the `analyses` table has **no password column**.
5. Terminal running the server: only request lines such as `POST /api/analyze 200`, never bodies.
