from flask import Blueprint, jsonify
from app.extensions import db
from app.models.lead import Lead
from flask_jwt_extended import jwt_required
from sqlalchemy import func
from datetime import datetime, timedelta

bp = Blueprint('dashboard', __name__, url_prefix='/api/dashboard')

@bp.route('/stats', methods=['GET'])
@jwt_required()
def get_stats():
    """Get dashboard statistics"""
    try:
        # Total leads
        total_leads = Lead.query.count()
        
        # New leads today
        today = datetime.utcnow().date()
        new_today = Lead.query.filter(
            func.date(Lead.created_at) == today
        ).count()
        
        # Qualified leads (status = qualified or converted)
        qualified_leads = Lead.query.filter(
            Lead.status.in_(['qualified', 'converted'])
        ).count()
        
        # Average score
        avg_score = db.session.query(func.avg(Lead.score)).scalar() or 0
        
        return jsonify({
            'totalLeads': total_leads,
            'newToday': new_today,
            'qualifiedLeads': qualified_leads,
            'avgScore': round(avg_score, 1)
        }), 200
        
    except Exception as e:
        return jsonify({'message': f'Error: {str(e)}'}), 500