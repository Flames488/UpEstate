from flask import abort
from flask_jwt_extended import get_jwt_identity
from app.models.user import User
from app.domain.permissions import is_admin


user = User.query.get(get_jwt_identity())


if not user or not is_admin(user.role):
abort(403, "Admin access required")