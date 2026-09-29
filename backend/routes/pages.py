"""Routes that serve the static frontend pages."""

from flask import Blueprint, current_app, send_from_directory

pages_bp = Blueprint("pages", __name__)


@pages_bp.get("/")
def index():
    return send_from_directory(current_app.static_folder, "index.html")


@pages_bp.get("/dashboard")
def dashboard():
    return send_from_directory(current_app.static_folder, "dashboard.html")


@pages_bp.get("/learn")
def learn():
    return send_from_directory(current_app.static_folder, "learn.html")
