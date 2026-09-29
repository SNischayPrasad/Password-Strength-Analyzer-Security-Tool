"""
Logging configuration with a redaction safety net.

The primary rule is simple: application code NEVER passes a password to a
logger. The RedactionFilter is defence-in-depth - if someone accidentally
logs a dict or JSON body containing a "password" key, the value is masked
before it reaches any log handler.
"""

import logging
import re

_PATTERNS = (
    # "password": "value"  or  'password': 'value'
    re.compile(r"""(["']?(?:password|passwd|pwd|secret)["']?\s*[:=]\s*)(["'])(.*?)(\2)""",
               re.IGNORECASE),
    # password=value in query-string / form style text
    re.compile(r"((?:password|passwd|pwd|secret)=)([^&\s]+)", re.IGNORECASE),
)

REDACTED = "[REDACTED]"


def redact(text: str) -> str:
    text = _PATTERNS[0].sub(lambda m: f"{m.group(1)}{m.group(2)}{REDACTED}{m.group(4)}", text)
    text = _PATTERNS[1].sub(lambda m: f"{m.group(1)}{REDACTED}", text)
    return text


class RedactionFilter(logging.Filter):
    """Mask password-like values in every log record."""

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            message = record.getMessage()
        except Exception:  # pragma: no cover - malformed record
            return True
        cleaned = redact(message)
        if cleaned != message:
            record.msg = cleaned
            record.args = ()
        return True


def configure_logging(level: int = logging.INFO) -> None:
    """Configure root logging once, with the redaction filter on every handler."""
    root = logging.getLogger()
    if not any(isinstance(f, RedactionFilter) for h in root.handlers for f in h.filters):
        handler = logging.StreamHandler()
        handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
        handler.addFilter(RedactionFilter())
        root.addHandler(handler)
    root.setLevel(level)
    for handler in root.handlers:
        if not any(isinstance(f, RedactionFilter) for f in handler.filters):
            handler.addFilter(RedactionFilter())
