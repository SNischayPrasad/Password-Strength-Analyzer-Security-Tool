"""
Privacy & security tests (T28-T30 plus the security-testing checklist).

These tests prove the privacy promises instead of just stating them:
the password never reaches storage, logs, responses, URLs, or browser storage.
"""

import inspect
import logging
import re
import sqlite3
from pathlib import Path

from backend.models.database import SCHEMA
from backend.services import password_generator
from backend.utils.logging_config import RedactionFilter, redact

PROJECT_ROOT = Path(__file__).resolve().parent.parent
SECRET_DEMO = "Zebra-Canary-4417-demo"


def _db_bytes(db_path) -> bytes:
    """Read the raw database file(s), including any write-ahead log."""
    data = b""
    for suffix in ("", "-wal", "-journal"):
        path = Path(str(db_path) + suffix)
        if path.exists():
            data += path.read_bytes()
    return data


def test_T28_password_not_stored(client, db_path):
    response = client.post("/api/analyze", json={"password": SECRET_DEMO, "record": True})
    assert response.get_json()["recorded"] is True
    raw = _db_bytes(db_path)
    assert SECRET_DEMO.encode() not in raw
    assert SECRET_DEMO.lower().encode() not in raw
    with sqlite3.connect(db_path) as conn:
        for table in ("analyses", "findings"):
            for row in conn.execute(f"SELECT * FROM {table}"):
                assert SECRET_DEMO not in " ".join(map(str, row))


def test_T29_password_not_logged(client, caplog):
    caplog.set_level(logging.DEBUG)
    client.post("/api/analyze", json={"password": SECRET_DEMO, "record": True,
                                      "context": {"first_name": "Zebra"}})
    client.post("/api/analyze", json={"password": "Q" * 999})  # error path
    assert SECRET_DEMO not in caplog.text
    assert "Q" * 50 not in caplog.text


def test_T30_analytics_storage_contains_only_metadata(repo):
    columns = set(repo.column_names("analyses")) | set(repo.column_names("findings"))
    assert columns == {
        "analysis_id", "score", "classification", "password_length", "unique_character_ratio",
        "weakness_count", "created_at", "finding_id", "finding_type", "severity", "description",
    }
    assert not any("password" == c or "hash" in c for c in columns)
    assert "password " not in SCHEMA.lower().replace("password_length", "")


def test_password_not_in_api_response(client):
    body = client.post("/api/analyze", json={"password": SECRET_DEMO}).get_data(as_text=True)
    assert SECRET_DEMO not in body


def test_password_not_in_error_messages(client):
    long_secret = SECRET_DEMO * 20
    body = client.post("/api/analyze", json={"password": long_secret}).get_data(as_text=True)
    assert SECRET_DEMO not in body


def test_password_never_sent_in_url_by_frontend():
    js = (PROJECT_ROOT / "frontend" / "js" / "analyzer.js").read_text(encoding="utf-8")
    common = (PROJECT_ROOT / "frontend" / "js" / "common.js").read_text(encoding="utf-8")
    assert 'postJSON("/api/analyze"' in js
    assert 'method: "POST"' in common
    assert "?password" not in js and "&password" not in js


def test_api_does_not_accept_password_via_query_string(client):
    response = client.post(f"/api/analyze?password={SECRET_DEMO}")
    assert response.status_code == 415  # body must be JSON; URL parameters are ignored


def test_frontend_uses_password_field():
    html = (PROJECT_ROOT / "frontend" / "index.html").read_text(encoding="utf-8")
    assert re.search(r'<input id="password" type="password"', html)
    assert 'autocomplete="new-password"' in html


def test_frontend_avoids_browser_storage_and_console_logging():
    for js_file in (PROJECT_ROOT / "frontend" / "js").glob("*.js"):
        code = js_file.read_text(encoding="utf-8")
        for pattern in (r"localStorage\.", r"sessionStorage\.", r"document\.cookie",
                        r"console\.log\(", r"\.innerHTML"):
            assert not re.search(pattern, code), f"{js_file.name}: {pattern}"


def test_generator_uses_secrets_not_random():
    source = inspect.getsource(password_generator)
    assert "import secrets" in source
    assert not re.search(r"^import random|^from random", source, re.MULTILINE)


def test_redaction_filter_masks_accidental_logging():
    assert "hunter2-demo" not in redact('{"password": "hunter2-demo"}')
    assert "hunter2-demo" not in redact("password=hunter2-demo&x=1")
    record = logging.LogRecord("t", logging.INFO, __file__, 1, "body=%s",
                               ('{"password": "hunter2-demo"}',), None)
    RedactionFilter().filter(record)
    assert "hunter2-demo" not in record.getMessage()


def test_debug_mode_off_by_default(app):
    assert app.config["DEBUG"] is False
