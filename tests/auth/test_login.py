def test_login_success(client, db_session):
    response = client.post("/auth/login", json={
        "email": "admin@test.com",
        "password": "securepassword"
    })

    assert response.status_code == 200
    data = response.get_json()
    assert "access_token" in data
    assert "refresh_token" in data


def test_login_invalid_password(client):
    response = client.post("/auth/login", json={
        "email": "admin@test.com",
        "password": "wrongpassword"
    })

    assert response.status_code == 401
    assert response.get_json()["error"] == "Invalid credentials"


def test_login_missing_fields(client):
    response = client.post("/auth/login", json={
        "email": "admin@test.com"
    })

    assert response.status_code == 400
