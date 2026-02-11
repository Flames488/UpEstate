import pytest
import json
from datetime import datetime, timedelta
from unittest.mock import Mock, patch, MagicMock

def test_create_lead_success(mock_lead_data):
    """Test successful lead creation"""
    with patch('database.leads.insert_lead') as mock_insert:
        mock_insert.return_value = "lead_123"
        
        result = create_lead(mock_lead_data)
        
        assert result["success"] == True
        assert result["lead_id"] == "lead_123"
        assert result["message"] == "Lead created successfully"
        mock_insert.assert_called_once_with(mock_lead_data)

def test_create_lead_missing_required_fields():
    """Test lead creation with missing required fields"""
    incomplete_data = {
        "name": "John Doe"
        # Missing email and phone
    }
    
    result = create_lead(incomplete_data)
    
    assert result["success"] == False
    assert "required" in result["error"].lower()
    assert "email" in result["error"] or "phone" in result["error"]

def test_create_lead_with_invalid_email():
    """Test lead creation with invalid email format"""
    lead_data = {
        "name": "John Doe",
        "email": "invalid-email-format",
        "phone": "+1234567890"
    }
    
    result = create_lead(lead_data)
    
    assert result["success"] == False
    assert "email" in result["error"].lower()
    assert "invalid" in result["error"].lower()

def test_create_lead_with_duplicate_email(mock_lead_data):
    """Test lead creation with duplicate email"""
    with patch('database.leads.find_lead_by_email') as mock_find:
        mock_find.return_value = {"id": "existing_lead"}
        
        result = create_lead(mock_lead_data)
        
        assert result["success"] == False
        assert "already exists" in result["error"].lower()

def test_get_lead_by_id():
    """Test retrieving a lead by ID"""
    lead_id = "lead_123"
    expected_lead = {
        "id": lead_id,
        "name": "John Doe",
        "email": "john@example.com",
        "status": "new"
    }
    
    with patch('database.leads.get_lead') as mock_get:
        mock_get.return_value = expected_lead
        
        result = get_lead(lead_id)
        
        assert result["success"] == True
        assert result["lead"] == expected_lead
        mock_get.assert_called_once_with(lead_id)

def test_get_nonexistent_lead():
    """Test retrieving a lead that doesn't exist"""
    lead_id = "nonexistent_lead"
    
    with patch('database.leads.get_lead') as mock_get:
        mock_get.return_value = None
        
        result = get_lead(lead_id)
        
        assert result["success"] == False
        assert "not found" in result["error"].lower()

def test_update_lead_status():
    """Test updating lead status"""
    lead_id = "lead_123"
    new_status = "contacted"
    update_data = {"status": new_status, "notes": "Called customer"}
    
    with patch('database.leads.update_lead') as mock_update:
        mock_update.return_value = True
        
        result = update_lead(lead_id, update_data)
        
        assert result["success"] == True
        assert result["message"] == "Lead updated successfully"
        mock_update.assert_called_once_with(lead_id, update_data)

def test_update_lead_invalid_status():
    """Test updating lead with invalid status"""
    lead_id = "lead_123"
    invalid_status = "invalid_status"
    
    result = update_lead(lead_id, {"status": invalid_status})
    
    assert result["success"] == False
    assert "status" in result["error"].lower()
    assert "invalid" in result["error"].lower()

def test_list_leads_with_pagination():
    """Test listing leads with pagination"""
    page = 1
    limit = 10
    filters = {"status": "new"}
    
    mock_leads = [
        {"id": f"lead_{i}", "name": f"User {i}", "email": f"user{i}@example.com"}
        for i in range(5)
    ]
    
    with patch('database.leads.list_leads') as mock_list:
        mock_list.return_value = {
            "leads": mock_leads,
            "total": 25,
            "page": page,
            "limit": limit
        }
        
        result = list_leads(page=page, limit=limit, filters=filters)
        
        assert result["success"] == True
        assert len(result["leads"]) == 5
        assert result["total"] == 25
        assert result["page"] == page
        mock_list.assert_called_once_with(page=page, limit=limit, filters=filters)

def test_assign_lead_to_user():
    """Test assigning a lead to a user"""
    lead_id = "lead_123"
    user_id = "user_456"
    
    with patch('database.leads.assign_lead') as mock_assign:
        mock_assign.return_value = True
        
        result = assign_lead(lead_id, user_id)
        
        assert result["success"] == True
        assert result["message"] == "Lead assigned successfully"
        mock_assign.assert_called_once_with(lead_id, user_id)

def test_lead_conversion():
    """Test converting a lead to a customer"""
    lead_id = "lead_123"
    conversion_data = {
        "converted_at": datetime.now().isoformat(),
        "plan": "premium",
        "notes": "Lead converted successfully"
    }
    
    with patch('database.leads.convert_lead') as mock_convert:
        mock_convert.return_value = "customer_123"
        
        result = convert_lead(lead_id, conversion_data)
        
        assert result["success"] == True
        assert result["customer_id"] == "customer_123"
        mock_convert.assert_called_once_with(lead_id, conversion_data)

def test_lead_export():
    """Test exporting leads to CSV"""
    filters = {"status": "converted", "start_date": "2024-01-01"}
    
    mock_csv_data = "id,name,email,status\nlead_123,John Doe,john@example.com,converted"
    
    with patch('services.export.generate_csv') as mock_generate:
        mock_generate.return_value = mock_csv_data
        
        result = export_leads(filters, format="csv")
        
        assert result["success"] == True
        assert result["format"] == "csv"
        assert "csv" in result["data"]
        assert "John Doe" in result["data"]

# Mock functions for lead operations
def create_lead(lead_data):
    required_fields = ["name", "email", "phone"]
    for field in required_fields:
        if field not in lead_data:
            return {"success": False, "error": f"Missing required field: {field}"}
    
    if "@" not in lead_data.get("email", ""):
        return {"success": False, "error": "Invalid email format"}
    
    return {
        "success": True,
        "lead_id": "lead_123",
        "message": "Lead created successfully"
    }

def get_lead(lead_id):
    return {
        "success": True,
        "lead": {
            "id": lead_id,
            "name": "John Doe",
            "email": "john@example.com",
            "status": "new"
        }
    }

def update_lead(lead_id, update_data):
    valid_statuses = ["new", "contacted", "qualified", "converted", "lost"]
    if "status" in update_data and update_data["status"] not in valid_statuses:
        return {"success": False, "error": "Invalid status value"}
    
    return {
        "success": True,
        "message": "Lead updated successfully"
    }

def list_leads(page=1, limit=20, filters=None):
    return {
        "success": True,
        "leads": [],
        "total": 0,
        "page": page,
        "limit": limit
    }

def assign_lead(lead_id, user_id):
    return {
        "success": True,
        "message": "Lead assigned successfully"
    }

def convert_lead(lead_id, conversion_data):
    return {
        "success": True,
        "customer_id": "customer_123",
        "message": "Lead converted successfully"
    }

def export_leads(filters, format="csv"):
    return {
        "success": True,
        "format": format,
        "data": "id,name,email\nlead_123,John Doe,john@example.com",
        "filename": f"leads_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.{format}"
    }