def test_admin_has_permission(client, access_token):
    response = client.get(
        "/admin/dashboard",
        headers={"Authorization": f"Bearer {access_token}"}
    )

    assert response.status_code == 200


def test_agent_forbidden_from_admin(client):
    agent_token = client.application.jwt_manager._create_access_token(
        identity={
            "id": 2,
            "role": "agent",
            "plan": "basic"
        }
    )

    response = client.get(
        "/admin/dashboard",
        headers={"Authorization": f"Bearer {agent_token}"}
    )

    assert response.status_code == 403


def test_missing_token_denied(client):
    response = client.get("/admin/dashboard")
    assert response.status_code == 401
