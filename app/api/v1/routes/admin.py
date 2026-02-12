from flask import Blueprint, request, jsonify
from app.middleware.admin_guard import admin_required
from app.models.user import User
from app.models.system_flag import SystemFlag
from app.extensions import db


admin_bp = Blueprint("admin", __name__, url_prefix="/admin")


@admin_bp.route("/users/<int:user_id>/suspend", methods=["POST"])
@admin_required
def suspend_user(user_id):
    """
    Suspend a user account.
    
    Args:
        user_id: ID of the user to suspend
    
    Returns:
        JSON response with suspension status
    """
    user = User.query.get_or_404(user_id)
    user.is_suspended = True
    db.session.commit()
    
    return jsonify({
        "status": "success",
        "message": f"User {user_id} suspended",
        "data": {"user_id": user_id, "suspended": True}
    }), 200


@admin_bp.route("/users/<int:user_id>/unsuspend", methods=["POST"])
@admin_required
def unsuspend_user(user_id):
    """
    Unsuspend a user account.
    
    Args:
        user_id: ID of the user to unsuspend
    
    Returns:
        JSON response with activation status
    """
    user = User.query.get_or_404(user_id)
    user.is_suspended = False
    db.session.commit()
    
    return jsonify({
        "status": "success", 
        "message": f"User {user_id} activated",
        "data": {"user_id": user_id, "suspended": False}
    }), 200


@admin_bp.route("/flags", methods=["GET", "POST"])
@admin_required  
def manage_system_flags():
    """
    Retrieve or update system feature flags.
    
    GET: Returns all system flags with their current status
    POST: Updates multiple system flags from JSON payload
    
    Returns:
        JSON response with all system flags and their states
    """
    if request.method == "POST":
        data = request.get_json(silent=True) or {}
        
        if not isinstance(data, dict):
            return jsonify({
                "status": "error",
                "message": "Invalid JSON payload"
            }), 400
            
        for key, value in data.items():
            flag = SystemFlag.query.get(key) or SystemFlag(key=key)
            flag.enabled = bool(value)
            db.session.add(flag)
        
        db.session.commit()
    
    # Return all flags for both GET and successful POST
    flags = {flag.key: flag.enabled for flag in SystemFlag.query.all()}
    
    return jsonify({
        "status": "success",
        "data": flags
    }), 200