from functools import wraps
from flask_jwt_extended import get_jwt_identity
from flask import jsonify
from app.models.subscription import Subscription
from datetime import datetime

def subscription_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        user_id = get_jwt_identity()
        subscription = Subscription.query.filter_by(user_id=user_id).first()

        if not subscription or not subscription.is_active():
            return jsonify({
                "error": "Active subscription required"
            }), 403

        return fn(*args, **kwargs)
    return wrapper
