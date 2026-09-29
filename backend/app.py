"""
Flask application entry point.

Run from the project root:

    python -m backend.app

then open http://127.0.0.1:5000 in your browser. The same server hosts the
frontend (HTML/CSS/JS) and the REST API, so there is no separate frontend
server and no CORS configuration to get wrong.
"""

import logging

from flask import Flask, jsonify, request
from werkzeug.exceptions import HTTPException

from backend.config import FRONTEND_DIR, Config
from backend.models.database import AnalyticsRepository
from backend.routes.api import api_bp
from backend.routes.pages import pages_bp
from backend.utils.logging_config import configure_logging
from backend.utils.rate_limiter import RateLimiter
from backend.utils.security_headers import apply_security_headers

logger = logging.getLogger(__name__)


def create_app(config_overrides: dict | None = None) -> Flask:
    """Application factory (makes testing with a temporary database easy)."""
    configure_logging()
    app = Flask(__name__, static_folder=str(FRONTEND_DIR), static_url_path="/assets")
    app.config.from_object(Config)
    # Keep dictionaries in the order we build them (e.g. length buckets 1-7, 8-11, ...).
    app.json.sort_keys = False
    if config_overrides:
        app.config.update(config_overrides)

    # Optional analytics - metadata only.
    app.extensions["analytics_repository"] = (
        AnalyticsRepository(app.config["ANALYTICS_DB_PATH"])
        if app.config["ANALYTICS_ENABLED"] else None
    )
    app.extensions["rate_limiters"] = {
        "analyze": RateLimiter(app.config["ANALYZE_RATE_LIMIT_PER_MINUTE"]),
        "generate": RateLimiter(app.config["GENERATE_RATE_LIMIT_PER_MINUTE"]),
    }

    app.register_blueprint(api_bp)
    app.register_blueprint(pages_bp)

    @app.after_request
    def add_headers(response):
        return apply_security_headers(response, request.path)

    # Generic JSON errors. Messages never include request data.
    @app.errorhandler(HTTPException)
    def handle_http_error(error: HTTPException):
        if not request.path.startswith("/api/"):
            return error
        messages = {
            404: "Endpoint not found.",
            405: "Method not allowed for this endpoint.",
            413: "Request body is too large.",
            415: "Request body must be JSON.",
        }
        return jsonify(error=messages.get(error.code, error.name)), error.code

    @app.errorhandler(Exception)
    def handle_unexpected_error(error: Exception):
        # Log the exception TYPE only: a traceback's local variables or
        # message could contain the submitted password.
        logger.error("Unhandled error on %s: %s", request.path, type(error).__name__)
        return jsonify(error="Internal server error."), 500

    return app


if __name__ == "__main__":
    application = create_app()
    print(f"Password Strength Analyzer running at http://{Config.HOST}:{Config.PORT}")
    application.run(host=Config.HOST, port=Config.PORT, debug=Config.DEBUG)
