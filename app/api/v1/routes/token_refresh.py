from flask import request, abort, jsonify, make_response
from app.models.refresh_token import RefreshToken
from app.security.tokens import generate_refresh_token, refresh_expiry
from app.extensions import db
import hashlib


raw = request.cookies.get("refresh_token")
if not raw:
abort(401)


hashed = hashlib.sha256(raw.encode()).hexdigest()


stored = RefreshToken.query.filter_by(token_hash=hashed, revoked=False).first()
if not stored or stored.expires_at < datetime.utcnow():
abort(401)


# Rotate
stored.revoked = True


new_raw, new_hashed = generate_refresh_token()
new_token = RefreshToken(
user_id=stored.user_id,
token_hash=new_hashed,
expires_at=refresh_expiry(),
)


db.session.add(new_token)
db.session.commit()


access_token = create_access_token(identity=stored.user_id, expires_delta=timedelta(minutes=10))


response = make_response(jsonify({"access_token": access_token}))
response.set_cookie("refresh_token", new_raw, httponly=True, secure=True, samesite="Strict")


return response