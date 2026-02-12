from flask import Blueprint, request
from flask_jwt_extended import jwt_required, get_jwt
from app.auth.rbac import require_permission
from app.billing.service import create_payment_intent

bp = Blueprint("billing", __name__, url_prefix="/api/v1/billing")

@bp.route("/pay", methods=["POST"])
@jwt_required()
@require_permission("billing:charge")
def pay():
    claims = get_jwt()
    return create_payment_intent(claims["tenant_id"], request.json)
