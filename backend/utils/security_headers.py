"""
HTTP security headers added to every response.

  * Content-Security-Policy: only load scripts/styles from this site, plus
    Chart.js from jsDelivr and fonts from Google Fonts. No inline scripts.
  * Cache-Control: no-store on API responses so analysis results and
    generated passwords are not kept in browser or proxy caches.
  * X-Content-Type-Options, X-Frame-Options, Referrer-Policy: standard
    hardening against MIME sniffing, clickjacking and referrer leaks.
  * Strict-Transport-Security is only meaningful over HTTPS; enable it at the
    HTTPS reverse proxy in production.
"""

CONTENT_SECURITY_POLICY = (
    "default-src 'self'; "
    "script-src 'self' https://cdn.jsdelivr.net; "
    "style-src 'self' https://fonts.googleapis.com; "
    "font-src 'self' https://fonts.gstatic.com; "
    "img-src 'self' data:; "
    "connect-src 'self'; "
    "object-src 'none'; "
    "base-uri 'none'; "
    "form-action 'self'; "
    "frame-ancestors 'none'"
)


def apply_security_headers(response, request_path: str):
    response.headers.setdefault("Content-Security-Policy", CONTENT_SECURITY_POLICY)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
    if request_path.startswith("/api/"):
        response.headers["Cache-Control"] = "no-store"
        response.headers["Pragma"] = "no-cache"
    return response
