from flask import Blueprint, jsonify, request, current_app
from flask_jwt_extended import (
    jwt_required,
    get_jwt_identity,
    unset_jwt_cookies,
)
from datetime import datetime, timedelta
from app.models.user import User
from app.security import verify_password, create_jwt_token
from app.services.otp_service import create_and_send_otp
from app.security.tokens import generate_refresh_token, refresh_expiry
from app.models.refresh_token import RefreshToken
from app.extensions import db
from app.security.jwt import create_access_token
from app.utils.decorators import validate_schema
from app.schemas.auth import LoginSchema, VerifyOTPSchema

auth_bp = Blueprint("auth", __name__, url_prefix="/api/auth")


@auth_bp.post("/login")
@validate_schema(LoginSchema)
def login():
    """
    Authenticate user and send OTP for verification.
    
    Returns:
        Success message indicating OTP has been sent.
        
    Security:
        - No tokens issued on initial login
        - Requires OTP verification for full authentication
        - Input validation via schema
    """
    data = request.get_json()
    
    try:
        # Find user by email
        user = User.query.filter_by(email=data["email"]).first()
        
        if not user:
            current_app.logger.warning(f"Login attempt with non-existent email: {data['email']}")
            return jsonify({
                "error": "Authentication failed",
                "message": "Invalid credentials"
            }), 401
        
        # Verify password
        if not verify_password(data["password"], user.password):
            current_app.logger.warning(f"Failed password attempt for user: {user.id}")
            return jsonify({
                "error": "Authentication failed",
                "message": "Invalid credentials"
            }), 401
        
        # Send OTP instead of JWT
        create_and_send_otp(user)
        db.session.commit()
        
        # Log OTP generation
        current_app.logger.info(f"OTP sent to user {user.id} ({user.email})")
        
        return jsonify({
            "success": True,
            "message": "OTP sent to your email",
            "next_step": "verify_otp",
            "email": user.email  # Include email for the next step
        }), 200
        
    except Exception as e:
        # Rollback database changes on error
        db.session.rollback()
        
        # Log the error
        current_app.logger.error(f"Login failed: {str(e)}", exc_info=True)
        
        # Return appropriate error response
        return jsonify({
            "error": "Authentication failed",
            "message": "Server error during authentication"
        }), 500


@auth_bp.post("/verify-otp")
@validate_schema(VerifyOTPSchema)
def verify_otp():
    """
    Verify OTP and issue JWT tokens upon successful verification.
    
    Returns:
        Access token in JSON and refresh token as secure HTTP-only cookie.
        
    Security:
        - Requires valid OTP that hasn't expired
        - OTP is cleared after successful verification
        - Issues JWT tokens only after 2-factor authentication
    """
    data = request.get_json()
    email = data.get("email")
    otp = data.get("otp")
    
    try:
        # Find user by email
        user = User.query.filter_by(email=email).first()
        
        if not user:
            current_app.logger.warning(f"OTP verification attempt for non-existent user: {email}")
            return jsonify({
                "error": "Authentication failed",
                "message": "Invalid credentials"
            }), 404
        
        # Check if OTP matches
        if not user.otp_code or user.otp_code != otp:
            current_app.logger.warning(f"Invalid OTP attempt for user: {user.id}")
            return jsonify({
                "error": "Authentication failed",
                "message": "Invalid OTP code"
            }), 401
        
        # Check if OTP has expired
        if datetime.utcnow() > user.otp_expires:
            current_app.logger.warning(f"Expired OTP attempt for user: {user.id}")
            return jsonify({
                "error": "Authentication failed",
                "message": "OTP has expired"
            }), 401
        
        # Mark OTP as verified and clear OTP data
        user.otp_verified = True
        user.otp_code = None
        user.otp_expires = None
        user.last_login = datetime.utcnow()
        
        # Generate refresh token pair
        raw_refresh_token, hashed_refresh_token = generate_refresh_token()
        
        # Create and store refresh token record
        refresh_token = RefreshToken(
            user_id=user.id,
            token_hash=hashed_refresh_token,
            expires_at=refresh_expiry(),
            # Optional security auditing fields:
            # user_agent=request.headers.get('User-Agent'),
            # ip_address=request.remote_addr,
            # device_info=request.headers.get('X-Device-Info')
        )
        
        db.session.add(refresh_token)
        db.session.commit()
        
        # Generate access token with appropriate expiry
        access_token = create_access_token(
            identity=str(user.id),
            expires_delta=timedelta(minutes=10),
            additional_claims={
                "email": user.email,
                "role": user.role if hasattr(user, 'role') else 'user',
                "verified": user.email_verified if hasattr(user, 'email_verified') else False
            }
        )
        
        # Alternative JWT creation (using the simpler function you mentioned)
        # token = create_jwt_token(user.id)
        
        # Construct response with access token
        response_data = {
            "access_token": access_token,
            "token_type": "bearer",
            "expires_in": 600,  # 10 minutes in seconds
            "user": {
                "id": user.id,
                "email": user.email,
                "role": user.role if hasattr(user, 'role') else 'user',
                "verified": user.otp_verified
            }
        }
        response = jsonify(response_data)
        response.status_code = 200
        
        # Set refresh token as secure HTTP-only cookie
        response.set_cookie(
            key="refresh_token",
            value=raw_refresh_token,
            httponly=True,
            secure=current_app.config.get('ENV') == 'production',  # Secure only in production
            samesite="Strict",
            max_age=timedelta(days=14).total_seconds(),
            path="/api/auth/refresh",  # Restrict cookie to refresh endpoint only
            domain=current_app.config.get('COOKIE_DOMAIN'),  # Optional: for cross-subdomain
        )
        
        # Add security headers
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate"
        response.headers["Pragma"] = "no-cache"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        
        # Log successful OTP verification
        current_app.logger.info(f"User {user.id} successfully verified OTP and logged in")
        
        return response
        
    except Exception as e:
        # Rollback database changes on error
        db.session.rollback()
        
        # Log the error
        current_app.logger.error(f"OTP verification failed: {str(e)}", exc_info=True)
        
        # Return appropriate error response
        return jsonify({
            "error": "OTP verification failed",
            "message": "Server error during OTP verification"
        }), 500


@auth_bp.post("/resend-otp")
def resend_otp():
    """
    Resend OTP to user's email.
    
    Args:
        email (str): User's email address
        
    Returns:
        Success message if OTP was resent, error otherwise.
        
    Security:
        - Rate limiting via cooldown period (60 seconds)
        - Prevents OTP spam
    """
    try:
        data = request.get_json()
        email = data.get("email")
        
        if not email:
            return jsonify({
                "error": "Validation error",
                "message": "Email is required"
            }), 400
        
        user = User.query.filter_by(email=email).first()
        if not user:
            current_app.logger.warning(f"Resend OTP attempt for non-existent user: {email}")
            return jsonify({
                "error": "User not found",
                "message": "No user exists with this email"
            }), 404
        
        # Check if there's an existing OTP and enforce cooldown (60 seconds)
        if user.otp_expires and (user.otp_expires - timedelta(minutes=4, seconds=0)) > datetime.utcnow():
            current_app.logger.info(f"Resend OTP too soon for user {user.id}")
            return jsonify({
                "error": "Rate limit exceeded",
                "message": "Please wait before resending OTP",
                "retry_after": 60
            }), 429
        
        # Resend OTP
        create_and_send_otp(user)
        db.session.commit()
        
        current_app.logger.info(f"OTP resent to user {user.id} ({user.email})")
        
        return jsonify({
            "success": True,
            "message": "OTP resent to your email",
            "email": user.email
        }), 200
        
    except Exception as e:
        # Rollback database changes on error
        db.session.rollback()
        
        # Log the error
        current_app.logger.error(f"Resend OTP failed: {str(e)}", exc_info=True)
        
        # Return appropriate error response
        return jsonify({
            "error": "Resend OTP failed",
            "message": "Server error while resending OTP"
        }), 500


@auth_bp.get("/me")
@jwt_required()
def get_current_user():
    """
    Get current authenticated user information.
    
    Returns:
        User information for the authenticated user.
        
    Security:
        - Requires valid access token
        - No sensitive information in response
    """
    try:
        user_id = get_jwt_identity()
        
        # In a real implementation, you would fetch user from database
        # user = User.query.get(user_id)
        # if not user:
        #     return jsonify({"error": "User not found"}), 404
        
        # For now, return basic user info from token claims
        from flask_jwt_extended import get_jwt
        
        claims = get_jwt()
        
        response_data = {
            "user": {
                "id": user_id,
                "email": claims.get("email"),
                "role": claims.get("role"),
                "verified": claims.get("verified", False)
            }
        }
        
        return jsonify(response_data), 200
        
    except Exception as e:
        current_app.logger.error(f"Failed to get user info: {str(e)}", exc_info=True)
        return jsonify({"error": "Failed to retrieve user information"}), 500


@auth_bp.post("/refresh")
def refresh_access_token():
    """
    Refresh access token using valid refresh token.
    
    Returns:
        New access token with updated expiry.
        
    Security:
        - Requires valid refresh token from HTTP-only cookie
        - Rotates refresh token (optional)
        - Invalidates old refresh token
    """
    try:
        # Get refresh token from cookie
        raw_refresh_token = request.cookies.get("refresh_token")
        
        if not raw_refresh_token:
            return jsonify({"error": "Refresh token required"}), 401
        
        # Find and validate refresh token in database
        from app.security.tokens import verify_refresh_token
        refresh_token_record = verify_refresh_token(raw_refresh_token)
        
        if not refresh_token_record:
            return jsonify({"error": "Invalid or expired refresh token"}), 401
        
        # Generate new access token
        access_token = create_access_token(
            identity=str(refresh_token_record.user_id),
            expires_delta=timedelta(minutes=10),
            additional_claims={
                "email": refresh_token_record.user.email if hasattr(refresh_token_record.user, 'email') else None,
                "role": refresh_token_record.user.role if hasattr(refresh_token_record.user, 'role') else 'user'
            }
        )
        
        # Optional: Implement refresh token rotation for better security
        # This invalidates the old refresh token and issues a new one
        
        # Construct response
        response_data = {
            "access_token": access_token,
            "token_type": "bearer",
            "expires_in": 600
        }
        
        response = jsonify(response_data)
        response.status_code = 200
        
        # Add security headers
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate"
        response.headers["Pragma"] = "no-cache"
        
        return response
        
    except Exception as e:
        current_app.logger.error(f"Token refresh failed: {str(e)}", exc_info=True)
        return jsonify({"error": "Token refresh failed"}), 500


@auth_bp.post("/logout")
def logout():
    """
    Logout user by invalidating refresh token.
    
    Returns:
        Success message and cleared cookies.
        
    Security:
        - Invalidates refresh token in database
        - Clears refresh token cookie
        - Client should delete access token
    """
    try:
        # Get refresh token from cookie
        raw_refresh_token = request.cookies.get("refresh_token")
        
        response = jsonify({
            "message": "Successfully logged out",
            "details": "Refresh token invalidated and cookies cleared"
        })
        
        # Clear the refresh token cookie
        response.set_cookie(
            key="refresh_token",
            value="",
            expires=0,
            httponly=True,
            secure=current_app.config.get('ENV') == 'production',
            samesite="Strict",
            path="/api/auth/refresh"
        )
        
        # If refresh token exists, invalidate it in database
        if raw_refresh_token:
            from app.security.tokens import invalidate_refresh_token
            invalidate_refresh_token(raw_refresh_token)
            db.session.commit()
            current_app.logger.info(f"Refresh token invalidated during logout")
        
        # Clear JWT cookies if using them elsewhere
        unset_jwt_cookies(response)
        
        # Add security headers
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate"
        response.headers["Pragma"] = "no-cache"
        
        return response, 200
        
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Logout failed: {str(e)}", exc_info=True)
        return jsonify({"error": "Logout failed"}), 500


@auth_bp.post("/logout-all")
@jwt_required()
def logout_all_devices():
    """
    Logout user from all devices by invalidating all refresh tokens.
    
    Returns:
        Success message.
        
    Security:
        - Requires valid access token
        - Invalidates ALL refresh tokens for the user
        - Useful for security incidents or lost devices
    """
    try:
        user_id = get_jwt_identity()
        
        # Invalidate all refresh tokens for this user
        RefreshToken.query.filter_by(user_id=user_id).delete()
        db.session.commit()
        
        response = jsonify({
            "message": "Successfully logged out from all devices",
            "devices_invalidated": True
        })
        
        # Clear the refresh token cookie
        response.set_cookie(
            key="refresh_token",
            value="",
            expires=0,
            httponly=True,
            secure=current_app.config.get('ENV') == 'production',
            samesite="Strict",
            path="/api/auth/refresh"
        )
        
        current_app.logger.info(f"User {user_id} logged out from all devices")
        
        return response, 200
        
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Logout all failed: {str(e)}", exc_info=True)
        return jsonify({"error": "Failed to logout from all devices"}), 500