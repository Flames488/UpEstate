# app/routes/admin_routes.py
from flask import Blueprint, request, jsonify, current_app
from flask_login import login_required, current_user
from app.models import AdminAlert, User, Subscription
from app.extensions import db
from datetime import datetime, timedelta

admin_bp = Blueprint("admin", __name__, url_prefix="/api/admin")

@admin_bp.route("/alerts", methods=["GET"])
@login_required
def get_alerts():
    """Get alerts with filtering"""
    # Check if user is admin
    if not current_user.is_admin:  # You'll need to add is_admin to User model
        return jsonify({"error": "Unauthorized"}), 403
    
    # Get query parameters
    alert_type = request.args.get("type")
    severity = request.args.get("severity")
    resolved = request.args.get("resolved")
    days = request.args.get("days", 7, type=int)
    
    # Build query
    query = AdminAlert.query
    
    # Filter by date
    cutoff_date = datetime.utcnow() - timedelta(days=days)
    query = query.filter(AdminAlert.created_at >= cutoff_date)
    
    # Apply filters
    if alert_type:
        query = query.filter(AdminAlert.alert_type == alert_type)
    if severity:
        query = query.filter(AdminAlert.severity == severity)
    if resolved:
        is_resolved = resolved.lower() == 'true'
        query = query.filter(AdminAlert.is_resolved == is_resolved)
    
    # Sort and paginate
    alerts = query.order_by(AdminAlert.created_at.desc()).limit(100).all()
    
    return jsonify({
        "alerts": [alert.to_dict() for alert in alerts],
        "count": len(alerts)
    })

@admin_bp.route("/alerts/<int:alert_id>/resolve", methods=["POST"])
@login_required
def resolve_alert(alert_id):
    """Mark alert as resolved"""
    if not current_user.is_admin:
        return jsonify({"error": "Unauthorized"}), 403
    
    alert = AdminAlert.query.get_or_404(alert_id)
    
    data = request.get_json()
    notes = data.get("notes")
    
    alert.resolve(current_user.id, notes)
    db.session.commit()
    
    return jsonify({
        "success": True,
        "alert": alert.to_dict(),
        "message": "Alert resolved successfully"
    })

@admin_bp.route("/alerts/<int:alert_id>/assign", methods=["POST"])
@login_required
def assign_alert(alert_id):
    """Assign alert to admin"""
    if not current_user.is_admin:
        return jsonify({"error": "Unauthorized"}), 403
    
    alert = AdminAlert.query.get_or_404(alert_id)
    
    data = request.get_json()
    assign_to = data.get("assign_to")
    
    if assign_to:
        # Verify assignee is admin
        assignee = User.query.get(assign_to)
        if not assignee or not assignee.is_admin:
            return jsonify({"error": "Assignee must be an admin"}), 400
    
    alert.assign(assign_to or current_user.id)
    db.session.commit()
    
    return jsonify({
        "success": True,
        "alert": alert.to_dict(),
        "message": "Alert assigned successfully"
    })

@admin_bp.route("/alerts/stats", methods=["GET"])
@login_required
def alert_stats():
    """Get alert statistics"""
    if not current_user.is_admin:
        return jsonify({"error": "Unauthorized"}), 403
    
    # Last 30 days
    cutoff = datetime.utcnow() - timedelta(days=30)
    
    stats = {
        "total": AdminAlert.query.filter(AdminAlert.created_at >= cutoff).count(),
        "critical": AdminAlert.query.filter(
            AdminAlert.created_at >= cutoff,
            AdminAlert.severity == "critical"
        ).count(),
        "unresolved": AdminAlert.query.filter(
            AdminAlert.created_at >= cutoff,
            AdminAlert.is_resolved == False
        ).count(),
        "by_type": {},
        "recent": []
    }
    
    # Get counts by type
    alerts_by_type = db.session.query(
        AdminAlert.alert_type,
        db.func.count(AdminAlert.id)
    ).filter(
        AdminAlert.created_at >= cutoff
    ).group_by(
        AdminAlert.alert_type
    ).all()
    
    stats["by_type"] = dict(alerts_by_type)
    
    # Get recent critical alerts
    recent_critical = AdminAlert.query.filter(
        AdminAlert.severity == "critical",
        AdminAlert.is_resolved == False
    ).order_by(
        AdminAlert.created_at.desc()
    ).limit(5).all()
    
    stats["recent"] = [alert.to_dict() for alert in recent_critical]
    
    return jsonify(stats)