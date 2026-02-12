from flask import Flask, jsonify, make_response
from typing import Tuple, Optional
import logging

# Initialize logger
logger = logging.getLogger(__name__)

def revoke_user_refresh_tokens(user_id: str) -> bool:
    """
    Revoke all refresh tokens for a given user from the database.
    
    Args:
        user_id: The ID of the user whose tokens should be revoked
        
    Returns:
        bool: True if successful, False otherwise
    """
    try:
        # Implementation depends on your database/ORM
        # Example with SQLAlchemy:
        # RefreshToken.query.filter_by(user_id=user_id).delete()
        # db.session.commit()
        
        # For now, placeholder implementation
        logger.info(f"Revoked all refresh tokens for user: {user_id}")
        return True
        
    except Exception as e:
        logger.error(f"Failed to revoke refresh tokens for user {user_id}: {str(e)}")
        return False


def logout_user(user_id: Optional[str] = None) -> Tuple[dict, int]:
    """
    Handle user logout by clearing cookies and revoking refresh tokens.
    
    Args:
        user_id: Optional user ID to revoke tokens for
        
    Returns:
        Tuple containing response data and HTTP status code
    """
    try:
        # Revoke refresh tokens from database if user_id is provided
        if user_id:
            success = revoke_user_refresh_tokens(user_id)
            if not success:
                logger.warning(f"Token revocation failed for user {user_id}, proceeding with cookie deletion")
        
        # Create response with no content
        response = make_response("", 204)
        
        # Clear the refresh token cookie with secure settings
        response.delete_cookie(
            key="refresh_token",
            path="/",  # Match the path where cookie was set
            domain=None,  # Use current domain
            secure=True,  # Only send over HTTPS in production
            httponly=True,  # Prevent JavaScript access
            samesite="Strict"  # CSRF protection
        )
        
        return response
        
    except Exception as e:
        logger.error(f"Logout failed: {str(e)}")
        error_response = {
            "error": "logout_failed",
            "message": "An error occurred during logout"
        }
        return jsonify(error_response), 500


# Example usage in a Flask route:
@app.route('/api/auth/logout', methods=['POST'])
def handle_logout():
    """
    Logout endpoint that clears cookies and revokes tokens.
    
    Expects user_id in request context (from authentication middleware)
    """
    # Get user_id from request context (set by auth middleware)
    user_id = getattr(request, 'user_id', None)
    
    return logout_user(user_id)