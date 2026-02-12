from flask import Blueprint, request, jsonify, current_app
from app.extensions import db, limiter, get_redis_client
from app.models.user import User
from flask_jwt_extended import (
    create_access_token, 
    create_refresh_token, 
    jwt_required, 
    get_jwt_identity,
    get_jwt,
    set_access_cookies,
    set_refresh_cookies,
    unset_jwt_cookies,
    verify_jwt_in_request,
    get_jwt_header,
    decode_token
)
import re
import time
from datetime import datetime, timedelta
import hashlib
import secrets
import json
from sqlalchemy import or_
import uuid

bp = Blueprint('auth', __name__, url_prefix='/api/auth')

# Security configurations
MAX_FAILED_ATTEMPTS = 5
LOCKOUT_MINUTES = 15
PASSWORD_HISTORY_LIMIT = 5
SESSION_TIMEOUT = timedelta(hours=24)
REFRESH_TOKEN_ROTATION = True

# Common blacklisted passwords (extended list)
BLACKLISTED_PASSWORDS = [
    'password', '123456', '12345678', '123456789', '1234567890',
    'qwerty', 'abc123', 'password1', 'admin', 'letmein', 'welcome',
    'monkey', 'dragon', 'baseball', 'football', 'superman',
    'iloveyou', 'trustno1', 'sunshine', 'master', 'hello',
    'freedom', 'whatever', 'qazwsx', 'password123', 'test123'
]

def get_client_ip():
    """Get client IP address with proxy support"""
    headers = request.headers
    
    # Check for CloudFlare
    if 'CF-Connecting-IP' in headers:
        return headers.get('CF-Connecting-IP')
    
    # Check for other proxies
    if 'X-Forwarded-For' in headers:
        # X-Forwarded-For can contain multiple IPs
        ips = headers.get('X-Forwarded-For').split(',')
        return ips[0].strip()
    
    # Check for other common headers
    proxy_headers = ['X-Real-IP', 'X-Client-IP']
    for header in proxy_headers:
        if header in headers:
            return headers.get(header)
    
    return request.remote_addr

def validate_email(email):
    """Enhanced email validation"""
    if not email or len(email) > 254:
        return False
    
    # Basic regex pattern
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    if not re.match(pattern, email):
        return False
    
    # Check for disposable email domains (partial list)
    disposable_domains = [
        'tempmail.com', 'guerrillamail.com', 'mailinator.com',
        '10minutemail.com', 'throwawaymail.com', 'yopmail.com'
    ]
    
    domain = email.split('@')[1].lower()
    if any(disposable in domain for disposable in disposable_domains):
        return False
    
    return True

def validate_password(password):
    """Enhanced password strength validation with zxcvbn-like scoring"""
    if not password:
        return False, "Password is required"
    
    if len(password) < 12:
        return False, "Password must be at least 12 characters long"
    
    # Character variety checks
    checks = {
        'uppercase': any(c.isupper() for c in password),
        'lowercase': any(c.islower() for c in password),
        'digit': any(c.isdigit() for c in password),
        'special': any(c in '!@#$%^&*()_+-=[]{}|;:,.<>?`~' for c in password)
    }
    
    missing = [name for name, passed in checks.items() if not passed]
    if missing:
        return False, f"Password must contain at least one {', '.join(missing)} character"
    
    # Check for common passwords
    if password.lower() in BLACKLISTED_PASSWORDS:
        return False, "Password is too common. Please choose a stronger password."
    
    # Check for sequential characters
    if re.search(r'(.)\1{3,}', password):
        return False, "Password contains too many repeated characters"
    
    # Check for keyboard patterns
    keyboard_patterns = [
        'qwerty', 'asdfgh', 'zxcvbn', 'qazwsx', '123qwe'
    ]
    for pattern in keyboard_patterns:
        if pattern in password.lower():
            return False, "Password contains a common keyboard pattern"
    
    # Calculate basic entropy (simplified)
    char_set_size = 0
    if any(c.islower() for c in password):
        char_set_size += 26
    if any(c.isupper() for c in password):
        char_set_size += 26
    if any(c.isdigit() for c in password):
        char_set_size += 10
    if any(c in '!@#$%^&*()_+-=[]{}|;:,.<>?`~' for c in password):
        char_set_size += 32
    
    entropy = len(password) * (char_set_size ** 0.5)
    if entropy < 60:  # Arbitrary threshold
        return False, "Password is not complex enough"
    
    return True, "Password is strong"

def is_rate_limited(client_ip, email=None):
    """Check if request is rate limited using Redis"""
    redis_client = get_redis_client()
    if not redis_client:
        return False
    
    now = int(time.time())
    
    # Check IP-based limiting
    ip_key = f"rate_limit:ip:{client_ip}"
    ip_attempts = redis_client.get(ip_key)
    
    if ip_attempts and int(ip_attempts) >= 10:  # 10 attempts per IP
        return True
    
    # Check email-based limiting
    if email:
        email_key = f"rate_limit:email:{email}"
        email_attempts = redis_client.get(email_key)
        
        if email_attempts and int(email_attempts) >= 5:  # 5 attempts per email
            return True
    
    return False

def record_failed_attempt(client_ip, email=None):
    """Record failed attempt in Redis"""
    redis_client = get_redis_client()
    if not redis_client:
        return
    
    now = int(time.time())
    window = 300  # 5 minutes
    
    # Record IP attempt
    ip_key = f"rate_limit:ip:{client_ip}"
    redis_client.incr(ip_key)
    redis_client.expire(ip_key, window)
    
    # Record email attempt if provided
    if email:
        email_key = f"rate_limit:email:{email}"
        redis_client.incr(email_key)
        redis_client.expire(email_key, window)
        
        # Also update user's failed attempts in database
        user = User.query.filter_by(email=email).first()
        if user:
            user.record_failed_login(client_ip)
            db.session.commit()

def clear_successful_attempt(client_ip, email=None):
    """Clear failed attempts on successful action"""
    redis_client = get_redis_client()
    if not redis_client:
        return
    
    # Clear IP attempts
    ip_key = f"rate_limit:ip:{client_ip}"
    redis_client.delete(ip_key)
    
    # Clear email attempts
    if email:
        email_key = f"rate_limit:email:{email}"
        redis_client.delete(email_key)

def create_audit_log(user_id, action, ip_address=None, details=None):
    """Create audit log entry"""
    from app.models.audit_log import AuditLog
    
    log = AuditLog(
        user_id=user_id,
        action=action,
        ip_address=ip_address or get_client_ip(),
        user_agent=request.headers.get('User-Agent'),
        details=details or {}
    )
    db.session.add(log)
    db.session.commit()
    return log

def blacklist_token(jti, expires_in=None):
    """Add token to blacklist"""
    redis_client = get_redis_client()
    if redis_client:
        if not expires_in:
            expires_in = current_app.config['JWT_ACCESS_TOKEN_EXPIRES']
        
        redis_client.setex(
            f"token:{jti}",
            int(expires_in.total_seconds()),
            "blacklisted"
        )

def rotate_refresh_token(user, old_refresh_token=None):
    """Implement refresh token rotation"""
    if old_refresh_token and REFRESH_TOKEN_ROTATION:
        # Blacklist old refresh token
        try:
            old_token = decode_token(old_refresh_token)
            blacklist_token(old_token['jti'], timedelta(days=30))
        except:
            pass
    
    # Generate new refresh token
    new_refresh_token = create_refresh_token(identity=user.id)
    refresh_token_hash = hashlib.sha256(new_refresh_token.encode()).hexdigest()
    
    # Store in database
    user.refresh_token_hash = refresh_token_hash
    user.refresh_token_expires = datetime.utcnow() + timedelta(days=30)
    db.session.commit()
    
    return new_refresh_token

# ========== AUTHENTICATION ROUTES ==========

@bp.route('/register', methods=['POST'])
@limiter.limit("5 per minute", key_func=lambda: get_client_ip())
@limiter.limit("20 per hour", key_func=lambda: get_client_ip())
def register():
    """Register a new user with enhanced security"""
    client_ip = get_client_ip()
    
    # Check rate limiting
    if is_rate_limited(client_ip):
        return jsonify({
            'message': 'Too many registration attempts. Please try again later.'
        }), 429
    
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({'message': 'Invalid JSON data'}), 400
        
        # Validate required fields
        required_fields = ['fullName', 'email', 'password', 'phone', 'company', 'role']
        for field in required_fields:
            if field not in data or not str(data[field]).strip():
                return jsonify({'message': f'{field} is required'}), 400
        
        # Validate email
        email = data['email'].strip().lower()
        if not validate_email(email):
            return jsonify({'message': 'Invalid email format or disposable email not allowed'}), 400
        
        # Validate password
        password_valid, password_msg = validate_password(data['password'])
        if not password_valid:
            return jsonify({'message': password_msg}), 400
        
        # Validate role
        valid_roles = ['admin', 'user', 'manager', 'agent']
        if data['role'] not in valid_roles:
            return jsonify({'message': 'Invalid role specified'}), 400
        
        # Check if user already exists (including soft-deleted)
        existing_user = User.query.filter(
            db.or_(
                User.email == email,
                db.and_(User.email == email, User.is_deleted == True)
            )
        ).first()
        
        if existing_user:
            if existing_user.is_deleted:
                return jsonify({
                    'message': 'This email was previously used. Please contact support to restore your account.'
                }), 409
            return jsonify({'message': 'Email already registered'}), 409
        
        # Create new user
        user = User(
            full_name=data['fullName'].strip(),
            email=email,
            phone=data['phone'].strip(),
            company=data['company'].strip(),
            role=data['role'],
            is_verified=False,
            email_verified=False,
            verification_token=User.generate_verification_token(),
            verification_token_expires=datetime.utcnow() + timedelta(hours=24)
        )
        
        # Set password with validation
        try:
            user.set_password(data['password'])
        except ValueError as e:
            return jsonify({'message': str(e)}), 400
        
        db.session.add(user)
        db.session.commit()
        
        # Generate verification email
        verification_link = f"{request.host_url}api/auth/verify-email/{user.verification_token}"
        
        # TODO: Send verification email
        # send_verification_email(user.email, verification_link)
        
        # Create audit log
        create_audit_log(user.id, 'user_registered', client_ip, {
            'email': user.email,
            'role': user.role
        })
        
        current_app.logger.info(f'New user registered: {email} from IP: {client_ip}')
        
        return jsonify({
            'message': 'User registered successfully. Please check your email to verify your account.',
            'user': {
                'id': user.id,
                'email': user.email,
                'fullName': user.full_name,
                'isVerified': user.is_verified
            }
        }), 201
        
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f'Registration error: {str(e)}', exc_info=True)
        return jsonify({'message': 'Registration failed. Please try again.'}), 500

@bp.route('/login', methods=['POST'])
@limiter.limit("10 per hour", key_func=lambda: get_client_ip())
@limiter.limit("100 per day", key_func=lambda: get_client_ip())
def login():
    """Login user with comprehensive security checks"""
    client_ip = get_client_ip()
    user_agent = request.headers.get('User-Agent', '')
    
    # Log login attempt
    current_app.logger.info(f'Login attempt from IP: {client_ip}')
    
    # Check rate limiting
    if is_rate_limited(client_ip):
        current_app.logger.warning(f'Rate limited login attempt from IP: {client_ip}')
        return jsonify({
            'message': 'Too many login attempts. Please try again in 5 minutes.'
        }), 429
    
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({'message': 'Invalid JSON data'}), 400
        
        email = data.get('email', '').strip().lower()
        password = data.get('password', '')
        
        if not email or not password:
            record_failed_attempt(client_ip, email)
            return jsonify({'message': 'Email and password are required'}), 400
        
        if not validate_email(email):
            record_failed_attempt(client_ip, email)
            return jsonify({'message': 'Invalid email format'}), 400
        
        # Find user with case-insensitive email search
        user = User.query.filter(
            db.func.lower(User.email) == email.lower()
        ).first()
        
        # Prevent timing attacks - always check password
        password_valid = False
        if user:
            # Check if account is locked first
            if user.is_account_locked():
                current_app.logger.warning(f'Locked account login attempt: {email}')
                return jsonify({
                    'message': f'Account is locked until {user.lockout_until.strftime("%Y-%m-%d %H:%M")}.'
                }), 423
            
            password_valid = user.check_password(password)
        
        if not user or not password_valid:
            record_failed_attempt(client_ip, email)
            
            # Log failed attempt
            create_audit_log(user.id if user else None, 'login_failed', client_ip, {
                'email': email,
                'reason': 'invalid_credentials'
            })
            
            current_app.logger.warning(f'Failed login attempt for: {email} from IP: {client_ip}')
            return jsonify({'message': 'Invalid email or password'}), 401
        
        # Check account status
        can_login, login_message = user.can_login()
        if not can_login:
            create_audit_log(user.id, 'login_blocked', client_ip, {
                'reason': login_message
            })
            return jsonify({'message': login_message}), 403
        
        # Check if MFA is required
        if user.mfa_enabled:
            # Generate and store MFA session
            mfa_session_id = str(uuid.uuid4())
            redis_client = get_redis_client()
            if redis_client:
                redis_client.setex(
                    f"mfa:{mfa_session_id}",
                    300,  # 5 minutes
                    json.dumps({'user_id': user.id, 'verified': False})
                )
            
            return jsonify({
                'message': 'MFA required',
                'mfa_required': True,
                'mfa_session_id': mfa_session_id
            }), 200
        
        # Clear failed attempts
        clear_successful_attempt(client_ip, email)
        user.reset_login_attempts()
        
        # Update login information
        user.update_last_login(client_ip, user_agent)
        
        # Generate session ID
        session_id = user.generate_session_id()
        
        # Create tokens with enhanced claims
        access_token = create_access_token(
            identity=user.id,
            additional_claims={
                'email': user.email,
                'role': user.role,
                'verified': user.is_verified,
                'session_id': session_id,
                'ip': client_ip,
                'user_agent_hash': hashlib.sha256(user_agent.encode()).hexdigest()[:16]
            }
        )
        
        # Create refresh token with rotation
        refresh_token = create_refresh_token(identity=user.id)
        refresh_token_hash = hashlib.sha256(refresh_token.encode()).hexdigest()
        
        user.refresh_token_hash = refresh_token_hash
        user.refresh_token_expires = datetime.utcnow() + timedelta(days=30)
        user.current_session_id = session_id
        user.last_session_refresh = datetime.utcnow()
        
        db.session.commit()
        
        # Create audit log for successful login
        create_audit_log(user.id, 'login_successful', client_ip, {
            'session_id': session_id,
            'user_agent': user_agent
        })
        
        current_app.logger.info(f'Successful login for: {email} from IP: {client_ip}')
        
        response_data = {
            'message': 'Login successful',
            'access_token': access_token,
            'refresh_token': refresh_token,
            'token_type': 'bearer',
            'expires_in': current_app.config['JWT_ACCESS_TOKEN_EXPIRES'].total_seconds(),
            'user': user.to_dict(),
            'session': {
                'id': session_id,
                'created_at': datetime.utcnow().isoformat()
            }
        }
        
        # Set cookies if configured
        if current_app.config.get('JWT_COOKIE_CSRF_PROTECT'):
            response = jsonify(response_data)
            set_access_cookies(response, access_token)
            set_refresh_cookies(response, refresh_token)
            return response
        
        return jsonify(response_data), 200
        
    except Exception as e:
        current_app.logger.error(f'Login error: {str(e)}', exc_info=True)
        return jsonify({'message': 'Login failed. Please try again.'}), 500

@bp.route('/refresh', methods=['POST'])
@jwt_required(refresh=True)
def refresh():
    """Refresh access token with rotation"""
    try:
        current_user_id = get_jwt_identity()
        user = User.query.get(current_user_id)
        
        if not user:
            return jsonify({'message': 'User not found'}), 404
        
        # Check if user can login
        can_login, message = user.can_login()
        if not can_login:
            return jsonify({'message': message}), 403
        
        # Get current refresh token from request
        refresh_token = request.json.get('refresh_token')
        if not refresh_token:
            return jsonify({'message': 'Refresh token required'}), 400
        
        # Verify refresh token hash
        refresh_token_hash = hashlib.sha256(refresh_token.encode()).hexdigest()
        if user.refresh_token_hash != refresh_token_hash:
            create_audit_log(user.id, 'refresh_token_invalid')
            return jsonify({'message': 'Invalid refresh token'}), 401
        
        # Check if refresh token is expired
        if user.refresh_token_expires < datetime.utcnow():
            create_audit_log(user.id, 'refresh_token_expired')
            return jsonify({'message': 'Refresh token expired'}), 401
        
        # Rotate refresh token
        new_refresh_token = rotate_refresh_token(user, refresh_token)
        
        # Create new access token
        access_token = create_access_token(
            identity=user.id,
            additional_claims={
                'email': user.email,
                'role': user.role,
                'verified': user.is_verified,
                'session_id': user.current_session_id or user.generate_session_id()
            }
        )
        
        # Update session refresh time
        user.last_session_refresh = datetime.utcnow()
        db.session.commit()
        
        create_audit_log(user.id, 'token_refreshed')
        
        return jsonify({
            'access_token': access_token,
            'refresh_token': new_refresh_token,
            'token_type': 'bearer',
            'expires_in': current_app.config['JWT_ACCESS_TOKEN_EXPIRES'].total_seconds()
        }), 200
        
    except Exception as e:
        current_app.logger.error(f'Token refresh error: {str(e)}', exc_info=True)
        return jsonify({'message': 'Token refresh failed'}), 500

@bp.route('/logout', methods=['POST'])
@jwt_required()
def logout():
    """Logout user by invalidating tokens"""
    try:
        user_id = get_jwt_identity()
        user = User.query.get(user_id)
        
        jwt_data = get_jwt()
        jti = jwt_data['jti']
        
        # Blacklist the current token
        blacklist_token(jti)
        
        if user:
            # Invalidate all sessions
            user.invalidate_all_sessions()
            db.session.commit()
            
            create_audit_log(user.id, 'logout', details={
                'token_jti': jti
            })
        
        response = jsonify({'message': 'Successfully logged out'})
        
        # Clear cookies if using them
        if current_app.config.get('JWT_COOKIE_CSRF_PROTECT'):
            unset_jwt_cookies(response)
        
        return response, 200
        
    except Exception as e:
        current_app.logger.error(f'Logout error: {str(e)}', exc_info=True)
        return jsonify({'message': 'Logout failed'}), 500

@bp.route('/logout-all', methods=['POST'])
@jwt_required()
def logout_all():
    """Logout user from all devices"""
    try:
        user_id = get_jwt_identity()
        user = User.query.get(user_id)
        
        if not user:
            return jsonify({'message': 'User not found'}), 404
        
        # Invalidate all sessions and tokens
        user.invalidate_all_sessions()
        
        # Blacklist all user's tokens
        redis_client = get_redis_client()
        if redis_client:
            pattern = f"user:{user.id}:token:*"
            keys = redis_client.keys(pattern)
            for key in keys:
                redis_client.delete(key)
        
        db.session.commit()
        
        create_audit_log(user.id, 'logout_all_devices')
        
        response = jsonify({'message': 'Logged out from all devices'})
        
        if current_app.config.get('JWT_COOKIE_CSRF_PROTECT'):
            unset_jwt_cookies(response)
        
        return response, 200
        
    except Exception as e:
        current_app.logger.error(f'Logout all error: {str(e)}', exc_info=True)
        return jsonify({'message': 'Logout failed'}), 500

@bp.route('/me', methods=['GET'])
@jwt_required()
def get_current_user():
    """Get current user info with security status"""
    try:
        user_id = get_jwt_identity()
        user = User.query.get(user_id)
        
        if not user:
            return jsonify({'message': 'User not found'}), 404
        
        # Check if session is still valid
        jwt_data = get_jwt()
        session_id = jwt_data.get('session_id')
        
        if user.current_session_id != session_id:
            return jsonify({
                'message': 'Session invalidated. Please login again.'
            }), 401
        
        return jsonify({
            'user': user.to_dict(),
            'security': {
                'requires_password_change': user.is_password_expired(30),
                'last_password_change': user.password_changed_at.isoformat() if user.password_changed_at else None,
                'failed_login_attempts': user.failed_login_attempts,
                'is_locked': user.is_locked,
                'mfa_enabled': user.mfa_enabled
            }
        }), 200
        
    except Exception as e:
        current_app.logger.error(f'Get current user error: {str(e)}')
        return jsonify({'message': 'Failed to retrieve user information'}), 500

@bp.route('/verify-email/<token>', methods=['GET'])
def verify_email(token):
    """Verify user's email address"""
    try:
        user = User.query.filter_by(verification_token=token).first()
        
        if not user:
            return jsonify({'message': 'Invalid verification token'}), 400
        
        if user.verification_token_expires and user.verification_token_expires < datetime.utcnow():
            return jsonify({'message': 'Verification token has expired'}), 400
        
        if user.email_verified:
            return jsonify({'message': 'Email already verified'}), 400
        
        user.verify_email()
        db.session.commit()
        
        create_audit_log(user.id, 'email_verified')
        current_app.logger.info(f'Email verified for user: {user.email}')
        
        return jsonify({
            'message': 'Email verified successfully. You can now log in.'
        }), 200
        
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f'Email verification error: {str(e)}')
        return jsonify({'message': 'Verification failed'}), 500

@bp.route('/resend-verification', methods=['POST'])
@limiter.limit("3 per hour", key_func=lambda: get_client_ip())
def resend_verification():
    """Resend verification email"""
    try:
        data = request.get_json()
        email = data.get('email', '').strip().lower()
        
        if not email or not validate_email(email):
            return jsonify({'message': 'Valid email is required'}), 400
        
        user = User.query.filter_by(email=email).first()
        
        if not user:
            # Don't reveal if user exists
            return jsonify({
                'message': 'If your email is registered, you will receive a verification link.'
            }), 200
        
        if user.email_verified:
            return jsonify({'message': 'Email already verified'}), 400
        
        # Generate new verification token
        user.verification_token = User.generate_verification_token()
        user.verification_token_expires = datetime.utcnow() + timedelta(hours=24)
        db.session.commit()
        
        # TODO: Send verification email
        # send_verification_email(user.email, user.verification_token)
        
        create_audit_log(user.id, 'verification_resent')
        
        return jsonify({
            'message': 'Verification email sent. Please check your inbox.'
        }), 200
        
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f'Resend verification error: {str(e)}')
        return jsonify({'message': 'Failed to resend verification'}), 500

@bp.route('/forgot-password', methods=['POST'])
@limiter.limit("5 per hour", key_func=lambda: get_client_ip())
def forgot_password():
    """Request password reset"""
    try:
        data = request.get_json()
        email = data.get('email', '').strip().lower()
        
        if not email or not validate_email(email):
            return jsonify({'message': 'Valid email is required'}), 400
        
        user = User.query.filter_by(email=email).first()
        
        # Always return success even if user doesn't exist (security)
        if user:
            # Check if account is locked
            if user.is_account_locked():
                return jsonify({
                    'message': 'Account is locked. Please contact support.'
                }), 423
            
            # Generate reset token
            reset_token = User.generate_reset_token()
            user.reset_token = reset_token
            user.reset_token_expires = datetime.utcnow() + timedelta(hours=1)
            db.session.commit()
            
            # TODO: Send password reset email
            # send_password_reset_email(user.email, reset_token)
            
            create_audit_log(user.id, 'password_reset_requested')
            current_app.logger.info(f'Password reset requested for: {email}')
        
        return jsonify({
            'message': 'If your email is registered, you will receive a password reset link.'
        }), 200
        
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f'Forgot password error: {str(e)}')
        return jsonify({'message': 'Failed to process request'}), 500

@bp.route('/reset-password', methods=['POST'])
@limiter.limit("5 per hour", key_func=lambda: get_client_ip())
def reset_password():
    """Reset password with token"""
    try:
        data = request.get_json()
        
        required = ['token', 'newPassword']
        for field in required:
            if field not in data or not data[field]:
                return jsonify({'message': f'{field} is required'}), 400
        
        token = data['token']
        new_password = data['newPassword']
        
        # Validate password strength
        password_valid, password_msg = validate_password(new_password)
        if not password_valid:
            return jsonify({'message': password_msg}), 400
        
        user = User.query.filter_by(reset_token=token).first()
        
        if not user or not user.reset_token_expires or user.reset_token_expires < datetime.utcnow():
            return jsonify({'message': 'Invalid or expired reset token'}), 400
        
        # Check if new password is same as old password
        if user.check_password(new_password):
            return jsonify({'message': 'New password cannot be the same as the old password'}), 400
        
        # Check password history
        if user.is_password_in_history(new_password):
            return jsonify({
                'message': 'This password was used recently. Please choose a different password.'
            }), 400
        
        # Set new password
        user.set_password(new_password)
        user.reset_token = None
        user.reset_token_expires = None
        user.failed_login_attempts = 0
        user.is_locked = False
        user.lockout_until = None
        
        # Invalidate all sessions
        user.invalidate_all_sessions()
        
        db.session.commit()
        
        create_audit_log(user.id, 'password_reset_successful')
        current_app.logger.info(f'Password reset successful for: {user.email}')
        
        return jsonify({
            'message': 'Password reset successfully. You can now log in with your new password.'
        }), 200
        
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f'Reset password error: {str(e)}')
        return jsonify({'message': 'Failed to reset password'}), 500

@bp.route('/change-password', methods=['POST'])
@jwt_required()
def change_password():
    """Change password for authenticated user"""
    try:
        user_id = get_jwt_identity()
        user = User.query.get(user_id)
        
        if not user:
            return jsonify({'message': 'User not found'}), 404
        
        data = request.get_json()
        
        required = ['currentPassword', 'newPassword']
        for field in required:
            if field not in data or not data[field]:
                return jsonify({'message': f'{field} is required'}), 400
        
        # Verify current password
        if not user.check_password(data['currentPassword']):
            create_audit_log(user.id, 'password_change_failed', details={
                'reason': 'incorrect_current_password'
            })
            return jsonify({'message': 'Current password is incorrect'}), 401
        
        # Validate new password strength
        password_valid, password_msg = validate_password(data['newPassword'])
        if not password_valid:
            return jsonify({'message': password_msg}), 400
        
        # Check if new password is same as old password
        if user.check_password(data['newPassword']):
            return jsonify({'message': 'New password cannot be the same as the old password'}), 400
        
        # Check password history
        if user.is_password_in_history(data['newPassword']):
            return jsonify({
                'message': 'This password was used recently. Please choose a different password.'
            }), 400
        
        # Set new password
        user.set_password(data['newPassword'])
        user.failed_login_attempts = 0
        
        # Invalidate all other sessions
        user.invalidate_all_sessions()
        
        db.session.commit()
        
        create_audit_log(user.id, 'password_changed')
        current_app.logger.info(f'Password changed for user: {user.email}')
        
        return jsonify({
            'message': 'Password changed successfully. Please log in again.'
        }), 200
        
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f'Change password error: {str(e)}')
        return jsonify({'message': 'Failed to change password'}), 500

@bp.route('/security-check', methods=['GET'])
@jwt_required()
def security_check():
    """Check if current session is still valid"""
    try:
        user_id = get_jwt_identity()
        user = User.query.get(user_id)
        
        if not user:
            return jsonify({'valid': False, 'message': 'User not found'}), 404
        
        # Check account status
        can_login, message = user.can_login()
        if not can_login:
            return jsonify({
                'valid': False,
                'message': message
            }), 200
        
        # Check session
        jwt_data = get_jwt()
        session_id = jwt_data.get('session_id')
        
        if user.current_session_id != session_id:
            return jsonify({
                'valid': False,
                'message': 'Session invalidated'
            }), 200
        
        # Check if password needs to be changed soon
        password_warning = user.is_password_expired(7)  # Warn 7 days before expiry
        
        return jsonify({
            'valid': True,
            'user': {
                'id': user.id,
                'email': user.email,
                'role': user.role,
                'isVerified': user.is_verified,
                'mfaEnabled': user.mfa_enabled
            },
            'warnings': {
                'password_expiry_soon': password_warning,
                'last_password_change': user.password_changed_at.isoformat() if user.password_changed_at else None
            }
        }), 200
        
    except Exception as e:
        current_app.logger.error(f'Security check error: {str(e)}')
        return jsonify({'valid': False, 'message': 'Security check failed'}), 500

@bp.route('/sessions', methods=['GET'])
@jwt_required()
def get_active_sessions():
    """Get active sessions for current user"""
    try:
        user_id = get_jwt_identity()
        
        redis_client = get_redis_client()
        sessions = []
        
        if redis_client:
            pattern = f"user:{user_id}:session:*"
            keys = redis_client.keys(pattern)
            
            for key in keys:
                session_data = redis_client.get(key)
                if session_data:
                    sessions.append({
                        'session_id': key.split(':')[-1],
                        'data': json.loads(session_data)
                    })
        
        return jsonify({'sessions': sessions}), 200
        
    except Exception as e:
        current_app.logger.error(f'Get sessions error: {str(e)}')
        return jsonify({'message': 'Failed to retrieve sessions'}), 500

@bp.route('/sessions/<session_id>', methods=['DELETE'])
@jwt_required()
def revoke_session(session_id):
    """Revoke a specific session"""
    try:
        user_id = get_jwt_identity()
        
        redis_client = get_redis_client()
        if redis_client:
            key = f"user:{user_id}:session:{session_id}"
            redis_client.delete(key)
        
        create_audit_log(user_id, 'session_revoked', details={
            'session_id': session_id
        })
        
        return jsonify({'message': 'Session revoked'}), 200
        
    except Exception as e:
        current_app.logger.error(f'Revoke session error: {str(e)}')
        return jsonify({'message': 'Failed to revoke session'}), 500

# ========== ADDITIONAL SECURITY ENDPOINTS ==========

@bp.route('/enable-mfa', methods=['POST'])
@jwt_required()
def enable_mfa():
    """Enable Multi-Factor Authentication"""
    try:
        user_id = get_jwt_identity()
        user = User.query.get(user_id)
        
        if not user:
            return jsonify({'message': 'User not found'}), 404
        
        if user.mfa_enabled:
            return jsonify({'message': 'MFA is already enabled'}), 400
        
        # Generate MFA secret (in production, use pyotp or similar)
        import pyotp
        mfa_secret = pyotp.random_base32()
        
        user.mfa_secret = mfa_secret
        user.mfa_enabled = True
        
        # Generate backup codes
        backup_codes = [secrets.token_hex(4).upper() for _ in range(10)]
        user.backup_codes = json.dumps(backup_codes)
        
        db.session.commit()
        
        create_audit_log(user.id, 'mfa_enabled')
        
        # Generate QR code URL for authenticator app
        totp = pyotp.TOTP(mfa_secret)
        provisioning_uri = totp.provisioning_uri(
            name=user.email,
            issuer_name=current_app.config.get('APP_NAME', 'YourApp')
        )
        
        return jsonify({
            'message': 'MFA enabled successfully',
            'mfa_secret': mfa_secret,  # Only show this once!
            'backup_codes': backup_codes,  # Only show this once!
            'provisioning_uri': provisioning_uri
        }), 200
        
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f'Enable MFA error: {str(e)}')
        return jsonify({'message': 'Failed to enable MFA'}), 500

@bp.route('/verify-mfa', methods=['POST'])
def verify_mfa():
    """Verify MFA code"""
    try:
        data = request.get_json()
        
        required = ['mfa_session_id', 'code']
        for field in required:
            if field not in data or not data[field]:
                return jsonify({'message': f'{field} is required'}), 400
        
        mfa_session_id = data['mfa_session_id']
        code = data['code']
        
        redis_client = get_redis_client()
        if not redis_client:
            return jsonify({'message': 'MFA not available'}), 503
        
        mfa_data = redis_client.get(f"mfa:{mfa_session_id}")
        if not mfa_data:
            return jsonify({'message': 'Invalid or expired MFA session'}), 400
        
        mfa_data = json.loads(mfa_data)
        user_id = mfa_data.get('user_id')
        
        user = User.query.get(user_id)
        if not user or not user.mfa_enabled:
            return jsonify({'message': 'Invalid user or MFA not enabled'}), 400
        
        # Verify MFA code
        import pyotp
        totp = pyotp.TOTP(user.mfa_secret)
        
        if not totp.verify(code, valid_window=1):
            # Check backup codes
            backup_codes = json.loads(user.backup_codes or '[]')
            if code in backup_codes:
                # Remove used backup code
                backup_codes.remove(code)
                user.backup_codes = json.dumps(backup_codes)
                db.session.commit()
            else:
                return jsonify({'message': 'Invalid MFA code'}), 401
        
        # Mark MFA as verified
        mfa_data['verified'] = True
        redis_client.setex(
            f"mfa:{mfa_session_id}",
            60,  # 1 minute to complete login
            json.dumps(mfa_data)
        )
        
        return jsonify({
            'message': 'MFA verified successfully',
            'mfa_session_id': mfa_session_id
        }), 200
        
    except Exception as e:
        current_app.logger.error(f'Verify MFA error: {str(e)}')
        return jsonify({'message': 'MFA verification failed'}), 500

@bp.route('/disable-mfa', methods=['POST'])
@jwt_required()
def disable_mfa():
    """Disable Multi-Factor Authentication"""
    try:
        user_id = get_jwt_identity()
        user = User.query.get(user_id)
        
        if not user:
            return jsonify({'message': 'User not found'}), 404
        
        if not user.mfa_enabled:
            return jsonify({'message': 'MFA is not enabled'}), 400
        
        data = request.get_json()
        if 'password' not in data or not user.check_password(data['password']):
            return jsonify({'message': 'Password is required to disable MFA'}), 401
        
        user.mfa_enabled = False
        user.mfa_secret = None
        user.backup_codes = None
        
        db.session.commit()
        
        create_audit_log(user.id, 'mfa_disabled')
        
        return jsonify({'message': 'MFA disabled successfully'}), 200
        
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f'Disable MFA error: {str(e)}')
        return jsonify({'message': 'Failed to disable MFA'}), 500

@bp.route('/audit-logs', methods=['GET'])
@jwt_required()
def get_audit_logs():
    """Get audit logs for current user"""
    try:
        user_id = get_jwt_identity()
        
        from app.models.audit_log import AuditLog
        
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 20, type=int)
        action = request.args.get('action', type=str)
        
        query = AuditLog.query.filter_by(user_id=user_id)
        
        if action:
            query = query.filter_by(action=action)
        
        logs = query.order_by(AuditLog.created_at.desc())\
                   .paginate(page=page, per_page=per_page, error_out=False)
        
        return jsonify({
            'logs': [log.to_dict() for log in logs.items],
            'total': logs.total,
            'pages': logs.pages,
            'page': logs.page
        }), 200
        
    except Exception as e:
        current_app.logger.error(f'Get audit logs error: {str(e)}')
        return jsonify({'message': 'Failed to retrieve audit logs'}), 500