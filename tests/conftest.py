"""
Shared pytest fixtures.

All passwords used in tests are SYNTHETIC demo values.
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from backend.app import create_app  # noqa: E402


@pytest.fixture()
def db_path(tmp_path):
    return tmp_path / "test_analytics.db"


@pytest.fixture()
def app(db_path):
    return create_app({
        "TESTING": True,
        "ANALYTICS_ENABLED": True,
        "ANALYTICS_DB_PATH": db_path,
        "RATE_LIMIT_ENABLED": False,
    })


@pytest.fixture()
def client(app):
    return app.test_client()


@pytest.fixture()
def repo(app):
    return app.extensions["analytics_repository"]
