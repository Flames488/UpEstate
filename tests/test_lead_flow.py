def test_create_lead_and_assign_agent(client, auth_headers):
    response = client.post(
        "/api/v1/leads",
        json={"name": "John Doe", "phone": "1234567890"},
        headers=auth_headers
    )
    assert response.status_code == 201
