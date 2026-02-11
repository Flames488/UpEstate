def test_pro_plan_can_access_premium_endpoint(client, access_token):
    response = client.get(
        "/leads/advanced-search",
        headers={"Authorization": f"Bearer {access_token}"}
    )

    assert response.status_code == 200


def test_basic_plan_blocked(client):
    basic_token = client.application.jwt_manager._create_access_token(
        identity={
            "id": 3,
            "role": "agent",
            "plan": "basic"
        }
    )

    response = client.get(
        "/leads/advanced-search",
        headers={"Authorization": f"Bearer {basic_token}"}
    )

    assert response.status_code == 402
    assert response.get_json()["error"] == "Upgrade plan required"
