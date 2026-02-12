from flask import Blueprint, jsonify
from flask_jwt_extended import get_csrf_token

csrf_bp = Blueprint("csrf", __name__, url_prefix="/auth")


@csrf_bp.get("/csrf-token")
def csrf_token():
    return jsonify({"csrfToken": get_csrf_token()})
