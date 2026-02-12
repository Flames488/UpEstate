from flask import Blueprint, jsonify
from app.health.checks import run_health_checks

health_bp = Blueprint("health", __name__)


@health_bp.route("/health", methods=["GET"])
def health():
    results = run_health_checks()

    status_code = 200
    if results["status"] == "degraded":
        status_code = 503

    return jsonify(results), status_code
