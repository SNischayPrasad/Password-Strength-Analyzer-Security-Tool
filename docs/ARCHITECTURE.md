# Architecture

## System architecture

```
User
 ↓
Secure web interface (index.html · password field hidden by default · CSP)
 ↓  POST /api/analyze   (JSON body, same origin, HTTPS in production)
Input validation (backend/utils/validation.py)
 ↓
In-memory analysis (backend/services/password_analyzer.py)
 ┌──────────────────────────────────────────────┐
 │ Length analyzer         length_analyzer.py    │
 │ Character analyzer      character_analyzer.py │
 │ Common-password checker common_password_checker.py │
 │ Sequence detector       pattern_detector.py   │
 │ Keyboard-pattern detector pattern_detector.py │
 │ Repetition detector     pattern_detector.py   │
 │ Date / structure detector pattern_detector.py │
 │ Context checker         context_checker.py    │
 │ Entropy estimator       entropy_estimator.py  │
 └──────────────────────────────────────────────┘
 ↓
Strength scoring engine (scoring_engine.py) → classification
 ↓
Suggestion engine (suggestion_engine.py)  +  policy checker (policy_checker.py)
 ↓
User (JSON result: no password, positions/types only)

Optional, opt-in only ("Add result to anonymous stats"):
Result → build_safe_record() allow-list → SQLite (models/database.py) → dashboard
```

**The password itself never travels into analytics storage.** `build_safe_record()` copies seven allow-listed fields, and the schema has no column that could hold a password.

## Folder structure

```
Password-Strength-Analyzer/
├── backend/
│   ├── app.py                  # Flask app factory, error handlers, headers
│   ├── config.py               # env-driven settings + admin policy
│   ├── routes/
│   │   ├── api.py              # REST endpoints
│   │   └── pages.py            # serves /, /dashboard, /learn
│   ├── services/               # pure-Python analysis engine (no Flask)
│   │   ├── password_analyzer.py   # orchestrator: analyze_password()
│   │   ├── length_analyzer.py     # analyze_length()
│   │   ├── character_analyzer.py  # analyze_characters()
│   │   ├── common_password_checker.py  # is_common_password(), dictionary words
│   │   ├── pattern_detector.py    # sequences, keyboard, repetition, dates, structure
│   │   ├── context_checker.py     # optional personal-info overlap
│   │   ├── entropy_estimator.py   # estimate_theoretical_entropy() + adjusted
│   │   ├── scoring_engine.py      # score, penalties, caps, classification
│   │   ├── suggestion_engine.py   # generate_suggestions()
│   │   ├── policy_checker.py      # POLICY PASS / FAIL
│   │   ├── password_generator.py  # secrets-based generator
│   │   └── wordlists.py           # local list loading, leetspeak normalization
│   ├── models/
│   │   └── database.py         # SQLite analytics, metadata only
│   └── utils/
│       ├── validation.py       # request validation, no echoing
│       ├── rate_limiter.py     # per-IP sliding window
│       ├── logging_config.py   # redaction filter
│       └── security_headers.py # CSP, no-store, etc.
├── frontend/
│   ├── index.html              # analyzer + generator
│   ├── learn.html              # education
│   ├── dashboard.html          # aggregate charts
│   ├── css/styles.css
│   └── js/ (common.js, analyzer.js, generator.js, dashboard.js)
├── data/
│   ├── common_passwords.txt    # small educational list
│   ├── common_words.txt        # small dictionary
│   └── passphrase_words.txt    # generator word list
├── demos/hashing_demo.py       # separate Argon2id demo
├── scripts/
│   ├── seed_demo_data.py       # synthetic dashboard data
│   └── analyze_cli.py          # getpass-based CLI
├── tests/                      # 73 pytest tests
├── docs/                       # explanations, API, testing, career kit
├── reports/PROJECT_REPORT.md
├── screenshots/                # proof images (synthetic data only)
├── README.md · requirements.txt · .env.example · .gitignore
```

| Folder | Why it exists |
|---|---|
| `backend/services` | The analysis engine as plain functions. You can test it and reuse it without a web server. |
| `backend/routes` | Thin HTTP layer: validate, call a service, return JSON. |
| `backend/models` | Everything that touches the database lives in one place, which makes it easy to audit for privacy. |
| `backend/utils` | Cross-cutting security concerns: validation, rate limiting, logging, headers. |
| `frontend` | Static UI served by Flask from the same origin, so no CORS is needed. |
| `data` | Local, reviewable word lists. Nothing is downloaded at runtime. |
| `demos` | Education kept separate from the product, so analyzer input can never end up hashed or stored. |
| `scripts` | Developer tools: demo data and the CLI. |
| `tests` | Automated proof of behaviour and privacy. |
| `docs`, `reports`, `screenshots` | Documentation and portfolio evidence. |

## Database design

```sql
CREATE TABLE analyses (
    analysis_id            TEXT PRIMARY KEY,           -- random UUID
    score                  INTEGER NOT NULL CHECK (score BETWEEN 0 AND 100),
    classification         TEXT    NOT NULL,
    password_length        INTEGER NOT NULL,
    unique_character_ratio REAL    NOT NULL,
    weakness_count         INTEGER NOT NULL,
    created_at             TEXT    NOT NULL            -- UTC, second precision
);

CREATE TABLE findings (
    finding_id    INTEGER PRIMARY KEY AUTOINCREMENT,
    analysis_id   TEXT NOT NULL REFERENCES analyses(analysis_id) ON DELETE CASCADE,
    finding_type  TEXT NOT NULL,     -- e.g. keyboard_pattern
    severity      TEXT NOT NULL,     -- critical/high/medium
    description   TEXT NOT NULL      -- fixed generic title, e.g. "Keyboard pattern"
);
```

**Why there is no password column, not even a hash:**
- Plaintext or encrypted passwords would turn a learning tool into a credential database.
- People often type their *real* password into strength checkers. A hash of a human-chosen password can be guessed offline, and a stored hash would reveal when the same password was checked again. The dashboard doesn't need it, so we don't collect it. This is **data minimization**.
- Descriptions are fixed generic titles, so no matched fragment can leak into storage.

## Technology choice

| | Option A: Beginner (chosen) | Option B: Modern |
|---|---|---|
| Frontend | HTML/CSS/vanilla JS | React |
| Backend | Flask | FastAPI |
| Storage | SQLite | SQLite / PostgreSQL |
| Charts | Chart.js | Recharts / Chart.js |
| Pros | No build step; every line is visible; one process serves everything; easy to explain in viva/interviews | Typed request models (Pydantic), automatic OpenAPI docs, component UI, async |
| Cons | Manual DOM updates; hand-written validation | Two toolchains (npm + Python), CORS config, more concepts at once |

**Recommendation:** Option A for a student project. It keeps attention on the *security* logic. The service layer is framework-independent, so moving to FastAPI later only means rewriting `routes/`.
