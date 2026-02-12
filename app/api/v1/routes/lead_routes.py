from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from app.services.lead_service import create_lead

bp = Blueprint('leads', __name__, url_prefix='/api/leads')

@bp.route('', methods=['POST'])
def create_lead_route():
    """Create a new lead from the capture form"""
    try:
        identity = get_jwt_identity()
        payload = request.get_json()
        
        # Validate required fields
        required_fields = ['name', 'email', 'phone', 'propertyType', 'budget', 'timeline']
        for field in required_fields:
            if field not in payload:
                return jsonify({'message': f'{field} is required'}), 400
        
        # Create lead using the service layer
        lead = create_lead(
            user_id=identity["id"],
            payload=payload
        )
        
        return jsonify({
            'message': 'Lead created successfully',
            'lead': lead.to_dict()
        }), 201
        
    except Exception as e:
        return jsonify({'message': f'Error: {str(e)}'}), 500

@bp.route('', methods=['GET'])
@jwt_required()
def get_leads():
    """Get all leads for authenticated user"""
    try:
        # Get all leads (in a real app, filter by agent_id)
        leads = Lead.query.order_by(Lead.created_at.desc()).all()
        
        return jsonify([lead.to_dict() for lead in leads]), 200
        
    except Exception as e:
        return jsonify({'message': f'Error: {str(e)}'}), 500

@bp.route('/<int:lead_id>', methods=['GET'])
@jwt_required()
def get_lead(lead_id):
    """Get a specific lead"""
    try:
        lead = Lead.query.get(lead_id)
        
        if not lead:
            return jsonify({'message': 'Lead not found'}), 404
        
        return jsonify(lead.to_dict()), 200
        
    except Exception as e:
        return jsonify({'message': f'Error: {str(e)}'}), 500

@bp.route('/<int:lead_id>', methods=['PUT'])
@jwt_required()
def update_lead(lead_id):
    """Update a lead"""
    try:
        lead = Lead.query.get(lead_id)
        
        if not lead:
            return jsonify({'message': 'Lead not found'}), 404
        
        data = request.get_json()
        
        # Update fields if provided
        if 'status' in data:
            lead.status = data['status']
        if 'name' in data:
            lead.name = data['name']
        if 'email' in data:
            lead.email = data['email']
        if 'phone' in data:
            lead.phone = data['phone']
        
        db.session.commit()
        
        return jsonify({
            'message': 'Lead updated successfully',
            'lead': lead.to_dict()
        }), 200
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'message': f'Error: {str(e)}'}), 500

@bp.route('/<int:lead_id>', methods=['DELETE'])
@jwt_required()
def delete_lead(lead_id):
    """Delete a lead"""
    try:
        lead = Lead.query.get(lead_id)
        
        if not lead:
            return jsonify({'message': 'Lead not found'}), 404
        
        db.session.delete(lead)
        db.session.commit()
        
        return jsonify({'message': 'Lead deleted successfully'}), 200
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'message': f'Error: {str(e)}'}), 500