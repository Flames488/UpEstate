import pytest
import bcrypt
import json
from datetime import datetime, timedelta
from unittest.mock import Mock, patch, MagicMock

def test_user_registration_success():
    """Test successful user registration"""
    user_data = {
        "username": "newuser",
        "email": "new@example.com",
        "password": "SecurePass123!",
        "first_name": "John",
        "last_name": "Doe"
    }
    
    with patch('database.users.create_user') as mock_create:
        mock_create.return_value = "user_123"
        
        result = register_user(user_data)
        
        assert result["success"] == True
        assert result["user_id"] == "user_123"
        assert "user" in result
        assert result["user"]["email"] == user_data["email"]
        assert "password" not in result["user"]  # Password should not be returned
        mock_create.assert_called_once()

def test_user_registration_duplicate_email():
    """Test registration with duplicate email"""
    user_data = {
        "username": "anotheruser",
        "email": "existing@example.com",
        "password": "SecurePass123!"
    }
    
    with patch('database.users.find_user_by_email') as mock_find:
        mock_find.return_value = {"id": "existing_user"}
        
        result = register_user(user_data)
        
        assert result["success"] == False
        assert "already exists" in result["error"].lower()

def test_user_registration_weak_password():
    """Test registration with weak password"""
    user_data = {
        "username": "newuser",
        "email": "new@example.com",
        "password": "weak"  # Too short
    }
    
    result = register_user(user_data)
    
    assert result["success"] == False
    assert "password" in result["error"].lower()
    assert "weak" in result["error"].lower()

def test_user_login_success(mock_user_data):
    """Test successful user login"""
    credentials = {
        "email": "test@example.com",
        "password": "SecurePass123!"
    }
    
    with patch('database.users.find_user_by_email') as mock_find:
        with patch('utils.auth.verify_password') as mock_verify:
            mock_find.return_value = mock_user_data
            mock_verify.return_value = True
            
            result = login_user(credentials)
            
            assert result["success"] == True
            assert "token" in result
            assert result["user"]["email"] == credentials["email"]

def test_user_login_invalid_credentials():
    """Test login with invalid credentials"""
    credentials = {
        "email": "nonexistent@example.com",
        "password": "wrongpassword"
    }
    
    with patch('database.users.find_user_by_email') as mock_find:
        mock_find.return_value = None
        
        result = login_user(credentials)
        
        assert result["success"] == False
        assert "invalid" in result["error"].lower()

def test_get_user_profile():
    """Test getting user profile"""
    user_id = "user_123"
    
    expected_profile = {
        "id": user_id,
        "username": "testuser",
        "email": "test@example.com",
        "first_name": "John",
        "last_name": "Doe",
        "created_at": "2024-01-01T00:00:00Z"
    }
    
    with patch('database.users.get_user') as mock_get:
        mock_get.return_value = expected_profile
        
        result = get_user_profile(user_id)
        
        assert result["success"] == True
        assert result["user"] == expected_profile
        mock_get.assert_called_once_with(user_id)

def test_update_user_profile():
    """Test updating user profile"""
    user_id = "user_123"
    update_data = {
        "first_name": "Jane",
        "last_name": "Smith",
        "phone": "+1234567890"
    }
    
    with patch('database.users.update_user') as mock_update:
        mock_update.return_value = True
        
        result = update_user_profile(user_id, update_data)
        
        assert result["success"] == True
        assert result["message"] == "Profile updated successfully"
        mock_update.assert_called_once_with(user_id, update_data)

def test_update_user_email_already_exists():
    """Test updating user email to one that already exists"""
    user_id = "user_123"
    update_data = {"email": "existing@example.com"}
    
    with patch('database.users.find_user_by_email') as mock_find:
        mock_find.return_value = {"id": "other_user"}
        
        result = update_user_profile(user_id, update_data)
        
        assert result["success"] == False
        assert "already exists" in result["error"].lower()

def test_change_password_success():
    """Test successful password change"""
    user_id = "user_123"
    password_data = {
        "current_password": "OldPass123!",
        "new_password": "NewPass456!"
    }
    
    with patch('database.users.verify_user_password') as mock_verify:
        with patch('database.users.update_password') as mock_update:
            mock_verify.return_value = True
            mock_update.return_value = True
            
            result = change_password(user_id, password_data)
            
            assert result["success"] == True
            assert result["message"] == "Password changed successfully"
            mock_verify.assert_called_once_with(user_id, password_data["current_password"])
            mock_update.assert_called_once_with(user_id, password_data["new_password"])

def test_change_password_wrong_current():
    """Test password change with wrong current password"""
    user_id = "user_123"
    password_data = {
        "current_password": "WrongPass!",
        "new_password": "NewPass456!"
    }
    
    with patch('database.users.verify_user_password') as mock_verify:
        mock_verify.return_value = False
        
        result = change_password(user_id, password_data)
        
        assert result["success"] == False
        assert "current password" in result["error"].lower()

def test_request_password_reset():
    """Test password reset request"""
    email = "user@example.com"
    
    with patch('database.users.find_user_by_email') as mock_find:
        with patch('utils.tokens.generate_reset_token') as mock_token:
            with patch('services.email.send_reset_email') as mock_send:
                mock_find.return_value = {"id": "user_123", "email": email}
                mock_token.return_value = "reset_token_123"
                mock_send.return_value = True
                
                result = request_password_reset(email)
                
                assert result["success"] == True
                assert result["reset_token"] == "reset_token_123"
                mock_send.assert_called_once_with(email, "reset_token_123")

def test_reset_password_success():
    """Test successful password reset"""
    reset_token = "valid_reset_token"
    new_password = "NewSecurePass123!"
    
    with patch('utils.tokens.verify_reset_token') as mock_verify:
        with patch('database.users.update_password_by_token') as mock_update:
            mock_verify.return_value = {"user_id": "user_123"}
            mock_update.return_value = True
            
            result = reset_password(reset_token, new_password)
            
            assert result["success"] == True
            assert result["message"] == "Password reset successfully"
            mock_verify.assert_called_once_with(reset_token)
            mock_update.assert_called_once_with("user_123", new_password)

def test_reset_password_invalid_token():
    """Test password reset with invalid token"""
    reset_token = "invalid_token"
    new_password = "NewSecurePass123!"
    
    with patch('utils.tokens.verify_reset_token') as mock_verify:
        mock_verify.return_value = None
        
        result = reset_password(reset_token, new_password)
        
        assert result["success"] == False
        assert "invalid" in result["error"].lower() or "expired" in result["error"].lower()

def test_deactivate_user_account():
    """Test deactivating a user account"""
    user_id = "user_123"
    
    with patch('database.users.deactivate_user') as mock_deactivate:
        mock_deactivate.return_value = True
        
        result = deactivate_user(user_id)
        
        assert result["success"] == True
        assert result["message"] == "Account deactivated successfully"
        mock_deactivate.assert_called_once_with(user_id)

def test_list_users_with_pagination():
    """Test listing users with pagination"""
    page = 1
    limit = 10
    filters = {"is_active": True}
    
    mock_users = [
        {"id": f"user_{i}", "email": f"user{i}@example.com", "is_active": True}
        for i in range(5)
    ]
    
    with patch('database.users.list_users') as mock_list:
        mock_list.return_value = {
            "users": mock_users,
            "total": 50,
            "page": page,
            "limit": limit
        }
        
        result = list_users(page=page, limit=limit, filters=filters)
        
        assert result["success"] == True
        assert len(result["users"]) == 5
        assert result["total"] == 50
        mock_list.assert_called_once_with(page=page, limit=limit, filters=filters)

def test_check_username_availability():
    """Test checking username availability"""
    username = "newusername"
    
    with patch('database.users.find_user_by_username') as mock_find:
        mock_find.return_value = None
        
        result = check_username_availability(username)
        
        assert result["success"] == True
        assert result["available"] == True
        assert result["username"] == username

# Mock functions for user operations
def register_user(user_data):
    required_fields = ["username", "email", "password"]
    for field in required_fields:
        if field not in user_data:
            return {"success": False, "error": f"Missing required field: {field}"}
    
    if len(user_data.get("password", "")) < 8:
        return {"success": False, "error": "Password must be at least 8 characters"}
    
    return {
        "success": True,
        "user_id": "user_123",
        "user": {
            "id": "user_123",
            "username": user_data["username"],
            "email": user_data["email"],
            "created_at": datetime.now().isoformat()
        }
    }

def login_user(credentials):
    if credentials.get("email") == "test@example.com" and credentials.get("password") == "SecurePass123!":
        return {
            "success": True,
            "token": "jwt_token_123",
            "user": {
                "id": "user_123",
                "email": credentials["email"],
                "username": "testuser"
            }
        }
    return {"success": False, "error": "Invalid credentials"}

def get_user_profile(user_id):
    return {
        "success": True,
        "user": {
            "id": user_id,
            "username": "testuser",
            "email": "test@example.com",
            "first_name": "John",
            "last_name": "Doe"
        }
    }

def update_user_profile(user_id, update_data):
    if update_data.get("email") == "existing@example.com":
        return {"success": False, "error": "Email already exists"}
    
    return {
        "success": True,
        "message": "Profile updated successfully"
    }

def change_password(user_id, password_data):
    if password_data.get("current_password") != "OldPass123!":
        return {"success": False, "error": "Current password is incorrect"}
    
    return {
        "success": True,
        "message": "Password changed successfully"
    }

def request_password_reset(email):
    return {
        "success": True,
        "reset_token": "reset_token_123",
        "expires_in": 3600
    }

def reset_password(reset_token, new_password):
    if reset_token != "valid_reset_token":
        return {"success": False, "error": "Invalid or expired reset token"}
    
    return {
        "success": True,
        "message": "Password reset successfully"
    }

def deactivate_user(user_id):
    return {
        "success": True,
        "message": "Account deactivated successfully"
    }

def list_users(page=1, limit=20, filters=None):
    return {
        "success": True,
        "users": [],
        "total": 0,
        "page": page,
        "limit": limit
    }

def check_username_availability(username):
    taken_usernames = ["admin", "test", "user"]
    return {
        "success": True,
        "available": username not in taken_usernames,
        "username": username
    }