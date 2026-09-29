"""
Request validation for the REST API.

Error messages are deliberately generic and NEVER echo the submitted
password (or context values) back to the client or into logs.
"""

from backend.services.context_checker import SUPPORTED_FIELDS


class RequestValidationError(ValueError):
    def __init__(self, message: str, status_code: int = 400):
        super().__init__(message)
        self.message = message
        self.status_code = status_code


def require_json_object(request) -> dict:
    if not request.is_json:
        raise RequestValidationError("Request body must be JSON (Content-Type: application/json).", 415)
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        raise RequestValidationError("Request body must be a JSON object.")
    return payload


def validate_analyze_payload(payload: dict, *, max_password_length: int,
                             max_context_length: int) -> tuple[str, dict, bool]:
    """Return (password, context, record) or raise RequestValidationError."""
    password = payload.get("password")
    if password is None or password == "":
        raise RequestValidationError("Password is required.")
    if not isinstance(password, str):
        raise RequestValidationError("Password must be a string.")
    if len(password) > max_password_length:
        raise RequestValidationError(
            f"Password exceeds the maximum supported length of {max_password_length} characters.")

    context_in = payload.get("context") or {}
    if not isinstance(context_in, dict):
        raise RequestValidationError("Context must be a JSON object.")
    context = {}
    for field in SUPPORTED_FIELDS:
        value = context_in.get(field)
        if value in (None, ""):
            continue
        if not isinstance(value, str) or len(value) > max_context_length:
            raise RequestValidationError(
                f"Context field '{field}' must be text of at most {max_context_length} characters.")
        context[field] = value

    record = payload.get("record", False)
    if not isinstance(record, bool):
        raise RequestValidationError("'record' must be true or false.")
    return password, context, record


def _bool_option(payload: dict, key: str, default: bool) -> bool:
    value = payload.get(key, default)
    if not isinstance(value, bool):
        raise RequestValidationError(f"'{key}' must be true or false.")
    return value


def validate_generate_payload(payload: dict) -> dict:
    length = payload.get("length", 20)
    if not isinstance(length, int) or isinstance(length, bool):
        raise RequestValidationError("'length' must be an integer.")
    return {
        "length": length,
        "use_uppercase": _bool_option(payload, "uppercase", True),
        "use_lowercase": _bool_option(payload, "lowercase", True),
        "use_digits": _bool_option(payload, "digits", True),
        "use_symbols": _bool_option(payload, "symbols", True),
        "exclude_ambiguous": _bool_option(payload, "exclude_ambiguous", False),
    }


def validate_passphrase_payload(payload: dict) -> dict:
    word_count = payload.get("word_count", 6)
    if not isinstance(word_count, int) or isinstance(word_count, bool):
        raise RequestValidationError("'word_count' must be an integer.")
    separator = payload.get("separator", "-")
    if not isinstance(separator, str):
        raise RequestValidationError("'separator' must be text.")
    return {"word_count": word_count, "separator": separator,
            "capitalize": _bool_option(payload, "capitalize", False)}
