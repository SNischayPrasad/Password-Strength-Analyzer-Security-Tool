"""
REST API.

    POST /api/analyze                 analyze a password (in memory only)
    POST /api/generate-password       generate a random password (secrets)
    POST /api/generate-passphrase     generate an example passphrase (secrets)
    GET  /api/dashboard/stats         aggregate, password-free statistics
    GET  /api/analytics/weaknesses    weakness-type frequencies
    GET  /api/policy                  the administrator-configured policy
    GET  /api/health                  liveness check

Privacy contract for /api/analyze:
  * the password arrives in a JSON body (never in the URL)
  * it is processed in memory and discarded when the request ends
  * it is never logged, stored, echoed in responses or in error messages
"""

import logging

from flask import Blueprint, current_app, jsonify, request

from backend.services.password_analyzer import PasswordValidationError, analyze_password
from backend.services.password_generator import (
    GeneratorError,
    SYMBOLS,
    generate_passphrase,
    generate_password,
    generated_password_entropy,
    passphrase_entropy,
)
from backend.services.policy_checker import policy_from_config
from backend.utils.rate_limiter import rate_limited
from backend.utils.validation import (
    RequestValidationError,
    require_json_object,
    validate_analyze_payload,
    validate_generate_payload,
    validate_passphrase_payload,
)

api_bp = Blueprint("api", __name__, url_prefix="/api")
logger = logging.getLogger(__name__)


def _repository():
    return current_app.extensions.get("analytics_repository")


@api_bp.errorhandler(RequestValidationError)
def handle_validation_error(error: RequestValidationError):
    return jsonify(error=error.message), error.status_code


@api_bp.post("/analyze")
@rate_limited("analyze")
def analyze():
    payload = require_json_object(request)
    password, context, record = validate_analyze_payload(
        payload,
        max_password_length=current_app.config["MAX_PASSWORD_LENGTH"],
        max_context_length=current_app.config["MAX_CONTEXT_FIELD_LENGTH"],
    )
    try:
        result = analyze_password(password, context=context,
                                  policy=policy_from_config(current_app.config),
                                  max_length=current_app.config["MAX_PASSWORD_LENGTH"])
    except PasswordValidationError as exc:
        raise RequestValidationError(str(exc)) from None

    result["recorded"] = False
    repo = _repository()
    if record and repo is not None:
        result["analysis_id"] = repo.record_analysis(result)
        result["recorded"] = True
        # Log only safe metadata - never the password or context.
        logger.info("analysis recorded: score=%s classification=%s",
                    result["score"], result["classification"])
    return jsonify(result)


@api_bp.post("/generate-password")
@rate_limited("generate")
def generate_password_route():
    payload = require_json_object(request)
    options = validate_generate_payload(payload)
    try:
        password = generate_password(**options)
    except GeneratorError as exc:
        raise RequestValidationError(str(exc)) from None
    alphabet = (26 * options["use_lowercase"] + 26 * options["use_uppercase"]
                + 10 * options["use_digits"] + len(SYMBOLS) * options["use_symbols"])
    return jsonify(
        password=password,
        length=len(password),
        entropy_bits=generated_password_entropy(len(password), alphabet),
        note="Generated with Python's secrets module. Not stored or logged by this server.",
    )


@api_bp.post("/generate-passphrase")
@rate_limited("generate")
def generate_passphrase_route():
    payload = require_json_object(request)
    options = validate_passphrase_payload(payload)
    try:
        passphrase = generate_passphrase(**options)
    except GeneratorError as exc:
        raise RequestValidationError(str(exc)) from None
    return jsonify(
        passphrase=passphrase,
        word_count=options["word_count"],
        entropy_bits=passphrase_entropy(options["word_count"]),
        note="EXAMPLE ONLY - demonstrates the format. Do not reuse a passphrase shown on screen.",
    )


@api_bp.get("/dashboard/stats")
def dashboard_stats():
    repo = _repository()
    if repo is None:
        return jsonify(error="Analytics are disabled on this server."), 404
    return jsonify(repo.get_dashboard_stats())


@api_bp.get("/analytics/weaknesses")
def weakness_stats():
    repo = _repository()
    if repo is None:
        return jsonify(error="Analytics are disabled on this server."), 404
    return jsonify(repo.get_weakness_stats())


@api_bp.get("/policy")
def policy():
    return jsonify(policy_from_config(current_app.config).to_dict())


@api_bp.get("/health")
def health():
    return jsonify(status="ok", analytics_enabled=_repository() is not None)
