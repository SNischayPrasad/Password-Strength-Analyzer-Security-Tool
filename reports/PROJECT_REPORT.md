# Project Report
## Password Strength Analyzer & Security Suggestion Tool

**Domain:** Cybersecurity: Application Security, Identity & Access Management
**Type:** Defensive security tool (educational)
**Technology:** Python 3, Flask, JavaScript, SQLite, Chart.js, pytest, argon2-cffi

---

### Abstract
Passwords remain the most widely deployed authentication factor. Many systems still judge them with composition rules that reward predictable choices such as `Password123!`. This project builds a privacy-focused web tool that assesses passwords the way attackers approach them: it measures length, character diversity and uniqueness, checks a local common-password list (including leetspeak variants), and detects sequences, keyboard walks, repetition, dates, dictionary words, word-plus-number structures and optional personal-information overlap. A theoretical entropy estimate (L × log₂N) is shown next to a pattern-adjusted estimate to show the limits of formula-based measures. A transparent scoring engine produces a 0–100 score and a five-level classification, and a suggestion engine gives specific remediation. Policy compliance is evaluated separately from strength. Passwords are processed only in memory and never stored, logged or transmitted to third parties, and 73 automated tests verify this. In testing, `123456` scored 0 (VERY WEAK), `Password123!` 38 (WEAK), `qwerty2026!` 25 (WEAK), a 16-character repeated string 24 (WEAK), and a randomly generated 20-character password about 98 (VERY STRONG).

### 1. Introduction
Account compromise often begins with a guessed, reused or phished password. Users receive little useful feedback when they choose one: most meters count character classes. This project provides explainable feedback grounded in how guessing attacks work, together with awareness material on passphrases, password managers, hashing and MFA.

### 2. Problem statement
Composition-based meters overrate predictable passwords and underrate long passphrases. Users aren't told *why* a password is weak, and some online checkers raise privacy concerns about where the password goes. The need is for a tool that (a) evaluates predictability, (b) explains its reasoning, and (c) provably protects the password it analyzes.

### 3. Objectives
1. Analyze length, diversity, uniqueness and common-password membership.
2. Detect sequential, keyboard, repetition, date, dictionary and structural patterns, plus optional personal-context overlap.
3. Estimate entropy theoretically and with pattern adjustment, and explain the limitations.
4. Produce a transparent 0–100 score, a classification and specific suggestions.
5. Provide a CSPRNG password generator and an admin-configurable policy checker.
6. Enforce and test privacy: no storage, logging, echoing or URL exposure of passwords.
7. Provide an aggregate, metadata-only dashboard and educational content.

### 4. Password security background
Attackers guess in order of likelihood: leaked-password lists, dictionaries, names and dates, keyboard patterns, and "mangling rules" (capitalize, append digits/symbols, leetspeak). **Credential stuffing** replays breached credentials on other sites and succeeds because of reuse. **Password spraying** tries a few common passwords across many accounts to evade lockouts. **Offline guessing** targets stolen hash databases, and its speed depends on the hashing algorithm.

### 5. Authentication security
Authentication proves identity. Authorization grants permissions. Password strength is one layer of authentication security, alongside MFA, rate limiting, secure hashing (Argon2id, scrypt, bcrypt, PBKDF2), account lockout and abuse protection, session security, phishing resistance and monitoring. A strong password alone cannot defend against phishing, malware, session theft or insecure storage at a third-party site.

### 6. Existing approaches
| Approach | Strength | Weakness |
|---|---|---|
| Composition rules | Simple to implement | Rewards predictable layouts; hurts usability |
| Length-only minimums | Aligns with guidance | Misses repetition and common passwords |
| Blocklists | Stops the worst passwords | Small lists miss variants |
| Pattern-based estimators (e.g. zxcvbn) | Realistic estimates | Larger, more complex; still estimates |
| Breach-corpus checks (k-anonymity) | Catches known leaked passwords | Requires a network call; privacy design needed |

This project combines length, a blocklist, pattern matching and an entropy ceiling in a small, explainable, fully local implementation.

### 7. Proposed system
A Flask service with a framework-independent analysis engine (`backend/services`), a thin REST layer, a static frontend served from the same origin, and optional SQLite analytics holding metadata only.

### 8. Architecture
User → secure web interface → POST `/api/analyze` → validation → in-memory analyzer (length, character, common-password, sequence, keyboard, repetition, date, dictionary, structure and context detectors; entropy estimator) → scoring engine → classification → suggestion engine and policy checker → JSON response. When the user opts in, an allow-listed record flows to SQLite for the dashboard. The password never crosses into storage. (Diagram in `README.md` and `docs/ARCHITECTURE.md`.)

### 9. Password analysis
`analyze_password(password, context)` validates input (string, ≤ 256 characters, no control characters), normalizes it with Unicode NFKC, runs each analyzer, and returns `score`, `classification`, `findings`, `suggestions`, `metrics`, `checks` and `policy`. The result never contains the password or context values.

### 10. Feature extraction
| Feature | Source |
|---|---|
| Length, length band | `length_analyzer.py` |
| Character classes, type count, unique count/ratio, pool size | `character_analyzer.py` |
| Common-password flag (exact / leet) | `common_password_checker.py` |
| Pattern matches with positions and lengths | `pattern_detector.py`, `common_password_checker.py`, `context_checker.py` |
| Repetition coverage | `pattern_detector.repetition_coverage()` |
| Theoretical and adjusted entropy | `entropy_estimator.py` |

### 11. Pattern detection
- **Sequences:** runs of ≥ 3 consecutive digits or letters, ascending or descending.
- **Keyboard walks:** longest-match against precomputed fragments (≥ 4 characters) of QWERTY/QWERTZ/AZERTY rows, column walks and keypad walks, in both directions. Straight digit runs are excluded to avoid double-reporting.
- **Repetition:** the regex `(.+?)\1+`. Single characters ×3+, or multi-character units covering 4+ characters. Coverage ≥ 50% is treated as high repetition.
- **Dates:** years 1900–2099, separated dates, and valid 6/8-digit compact dates.
- **Structure:** a known word followed by digits/symbols, or the "Capitalized word + digits + symbol" layout.
- **Context:** optional name, birth year and organization tokens (≥ 3 characters, also reversed and leet-normalized).

### 12. Common-password detection
A small local educational list of generic weak passwords (no leaked credentials or personal data) is compared after lowercasing and leetspeak normalization. A trailing digit/symbol run is preserved, so `p@ssw0rd1` maps to `password1`. A match triggers a critical finding, the message "Your password matches a commonly used password pattern and should not be used.", and a score cap of 10.

### 13. Entropy concepts
Theoretical entropy is `L × log₂(N)`, which is valid only for uniformly random selection. The pattern-adjusted estimate greedily covers the password with detected patterns, choosing those that save the attacker the most bits first. Each pattern is priced at an approximate attacker cost: a dictionary word at log₂(|dictionary|) plus capitalization/leet bits; a sequence at start + direction + length; a year at log₂(200); personal information at about 3 bits. Remaining characters cost log₂(N) each. Example: `Password123!` scores 78.8 bits theoretical but 23.0 bits adjusted. Guess-time scenarios are labelled educational, because real resistance depends on the attacker model, hashing, work factor, rate limiting and online/offline conditions.

### 14. Strength scoring
Contributions: length 35, diversity 15, unique ratio 10, pattern resistance 20 (−5 per pattern type), not-common 10, unpredictability 10 (from adjusted bits). Penalties by type (common 40, personal 20, keyboard 12, structure 10, repetition 8 or 25 when dominant, sequence 8 (+2 if ≥ 5 long), dictionary 6, date 6) are combined with weights 1, ½, ¼ … so overlapping findings aren't double-counted. Caps: common → 10; length < 6/8/10/12 → 20/30/55/75; an entropy ceiling of 15 + adjusted bits. Bands: 0–20 VERY WEAK, 21–40 WEAK, 41–60 MODERATE, 61–80 STRONG, 81–100 VERY STRONG. These bands are **project-defined, not a universal standard**, and the full breakdown is shown to the user.

### 15. Recommendation engine
Each finding type maps to specific advice (e.g. "Avoid keyboard walks such as qwerty, asdf or 1qaz"). Length and variety guidance follow, and hygiene advice (unique passwords, password manager, MFA) is always included. Suggestions never quote the password.

### 16. Password generator
Uses `secrets.choice` and `secrets.SystemRandom().shuffle`, guarantees each selected class, and offers lengths 16/20/24 (8–128 via the API). An example passphrase generator draws words from a local list. The ~484-word demo list gives about 8.9 bits per word, and the report recommends the EFF 7,776-word list (~12.9 bits per word) for real use. Generated values are never stored, and API responses are `no-store`.

### 17. Policy checker
Admin-configurable: minimum length (12), maximum length (128), common-password block, personal-info block, spaces allowed. The output is POLICY PASS/FAIL with per-rule results, shown separately from strength. Example: `Welcome2026!` → POLICY PASS but WEAK (40).

### 18. Secure password storage concepts
A separate demo (`demos/hashing_demo.py`) implements `hash_password()` / `verify_password()` with Argon2id (m = 19 MiB, t = 2, p = 1). It shows that salts make hashes unique, that verification is one-way, and how much cheaper SHA-256 is per hash. It uses a synthetic password and is never connected to analyzer input. Hashing is one-way; encryption is reversible and therefore unsuitable for password storage.

### 19. Privacy design
In-memory processing; POST JSON only; no password column; allow-list record builder; generic finding titles in storage; no logging of bodies plus a redaction filter; generic error messages; `Cache-Control: no-store`; CSP and hardening headers; debug off by default; frontend `type="password"`, textContent rendering, no browser storage, and fields cleared on `pagehide`; real-time requests never recorded; context values never stored or echoed.

### 20. Dashboard
Metadata-only statistics: total analyses, per-class counts, average score, and five charts (strength distribution, score distribution, most common weakness types, length distribution, weaknesses per analysis). Each chart has a table fallback. A seeding script generates synthetic data.

### 21. Testing
73 pytest tests: the 30 required scenarios (T01–T30), engine tests, API tests (validation, status codes, headers, rate limiting) and hashing-demo tests. All pass. See `docs/TESTING.md`.

### 22. Security testing
Automated verification that the password is absent from raw database bytes, logs, API responses, error messages and URLs; that the input is a password field; that frontend code uses no browser storage, cookies, console logging or innerHTML; that the generator imports `secrets`; that redaction works; and that debug is off. Manual DevTools steps are documented for screenshots.

### 23. Results
| Input (synthetic) | Score | Class | Key findings |
|---|---|---|---|
| `123456` | 0 | VERY WEAK | common, sequence |
| `Password123!` | 38 | WEAK | dictionary word, structure, sequence (theoretical 78.8 bits vs adjusted 23.0) |
| `aaaaaaaaaaaaaaaa` | 24 | WEAK | high repetition |
| `qwerty2026!` | 25 | WEAK | keyboard, year, structure |
| `Welcome2026!` | 40 | WEAK | structure, year, but POLICY PASS |
| `Rahul@123` (+ demo name) | 24 | WEAK | personal info, structure, sequence |
| random 6-word passphrase | ~86 | VERY STRONG | passphrase detected |
| random 20-char password | ~98 | VERY STRONG | none |

The results confirm the project's thesis: composition diversity without unpredictability scores poorly, while length combined with randomness scores well.

### 24. Limitations
Small educational word lists (real attackers use billions of leaked passwords); heuristic entropy; limited keyboard layouts; in-memory single-process rate limiting; no breach-corpus lookup; Python strings can't be securely wiped; scoring weights are project-defined; guess times are illustrative.

### 25. Future scope
Better estimators (a zxcvbn-style matcher with large ranked dictionaries); configurable enterprise policies with per-tenant blocklists; opt-in privacy-preserving breach checks using k-anonymity hash-prefix range queries; password-manager integration concepts; enterprise IAM/SSO integration and SSO security education; MFA, passwordless, WebAuthn and passkey awareness modules; localization; accessibility audits (screen readers, contrast); organization-level aggregate reporting without collecting passwords; CI pipeline and containerized HTTPS deployment.

### 26. Conclusion
The project shows that meaningful password assessment requires more than composition rules: length, unpredictability, pattern resistance, common-password checks and context all matter, and even then the result is an estimate. By pairing an explainable analysis engine with privacy by design, verified through automated tests, the tool gives users useful feedback without creating a new place for passwords to leak. It also demonstrates core skills for application security, IAM and secure software roles.

### References
- NIST SP 800-63B, *Digital Identity Guidelines: Authentication and Lifecycle Management*.
- OWASP *Password Storage Cheat Sheet* and *Authentication Cheat Sheet*.
- D. Wheeler, "zxcvbn: Low-Budget Password Strength Estimation," USENIX Security 2016.
- EFF *Dice-Generated Passphrases* word lists.
- Python documentation: `secrets` — Generate secure random numbers for managing secrets.
