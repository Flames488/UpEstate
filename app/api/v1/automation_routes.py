from flask import Blueprint, request
from flask_jwt_extended import jwt_required, get_jwt
from app.auth.rbac import require_permission
from app.automation.service import run_automation
from app.automation.quotas import check_quota
from app.db.tenant_scope import scope_query
from app.models.tenant import Tenant

bp = Blueprint("automation", __name__, url_prefix="/api/v1/automation")

@bp.route("/run", methods=["POST"])
@jwt_required()
@require_permission("automation:run")
def run():
    claims = get_jwt()
    tenant_id = claims["tenant_id"]

    tenant = scope_query(Tenant.query, tenant_id).first()
    check_quota(tenant.plan, tenant.automation_used)

    return run_automation(tenant_id, request.json)
