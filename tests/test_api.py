"""REST API tests (synthetic passwords only)."""

from backend.app import create_app


def test_analyze_endpoint_returns_structured_result(client):
    response = client.post("/api/analyze", json={"password": "Password123!"})
    assert response.status_code == 200
    data = response.get_json()
    for key in ("score", "classification", "findings", "suggestions", "metrics", "policy"):
        assert key in data
    assert data["recorded"] is False


def test_analyze_requires_json(client):
    response = client.post("/api/analyze", data="password=abc")
    assert response.status_code == 415


def test_analyze_rejects_empty_password(client):
    response = client.post("/api/analyze", json={"password": ""})
    assert response.status_code == 400
    assert response.get_json()["error"] == "Password is required."


def test_analyze_rejects_non_string_password(client):
    assert client.post("/api/analyze", json={"password": 123456}).status_code == 400


def test_analyze_rejects_too_long_password_without_echo(client):
    password = "Z" * 300
    response = client.post("/api/analyze", json={"password": password})
    assert response.status_code == 400
    assert password not in response.get_data(as_text=True)


def test_analyze_get_not_allowed(client):
    assert client.get("/api/analyze").status_code == 405


def test_generate_password_endpoint(client):
    response = client.post("/api/generate-password", json={"length": 24})
    assert response.status_code == 200
    assert len(response.get_json()["password"]) == 24


def test_generate_password_validation(client):
    assert client.post("/api/generate-password", json={"length": 4}).status_code == 400
    assert client.post("/api/generate-password", json={
        "uppercase": False, "lowercase": False, "digits": False, "symbols": False}).status_code == 400


def test_generate_passphrase_endpoint(client):
    data = client.post("/api/generate-passphrase", json={"word_count": 5}).get_json()
    assert len(data["passphrase"].split("-")) == 5
    assert "EXAMPLE ONLY" in data["note"]


def test_dashboard_and_weakness_endpoints(client):
    client.post("/api/analyze", json={"password": "qwerty2026!", "record": True})
    stats = client.get("/api/dashboard/stats").get_json()
    assert stats["total_analyses"] == 1
    assert stats["classification_counts"]["WEAK"] == 1
    weaknesses = client.get("/api/analytics/weaknesses").get_json()
    assert any(w["type"] == "keyboard_pattern" for w in weaknesses["weakness_types"])


def test_policy_endpoint(client):
    assert client.get("/api/policy").get_json()["minimum_length"] == 12


def test_security_headers(client):
    response = client.post("/api/analyze", json={"password": "Password123!"})
    assert response.headers["Cache-Control"] == "no-store"
    assert "default-src 'self'" in response.headers["Content-Security-Policy"]
    assert response.headers["X-Frame-Options"] == "DENY"


def test_rate_limiting(tmp_path):
    app = create_app({"TESTING": True, "ANALYTICS_DB_PATH": tmp_path / "rl.db",
                      "ANALYZE_RATE_LIMIT_PER_MINUTE": 3, "RATE_LIMIT_ENABLED": True})
    client = app.test_client()
    codes = [client.post("/api/analyze", json={"password": "demo-rate-limit"}).status_code
             for _ in range(4)]
    assert codes == [200, 200, 200, 429]


def test_frontend_pages_served(client):
    for path in ("/", "/dashboard", "/learn"):
        assert client.get(path).status_code == 200


def test_dashboard_buckets_keep_logical_order(client):
    stats = client.get("/api/dashboard/stats").get_json()
    assert list(stats["length_distribution"]) == ["1-7", "8-11", "12-15", "16-19", "20+"]
