import pytest
from httpx import AsyncClient

BASE = "/api/v1/auth"

VALID_USER = {
    "full_name": "Profile User",
    "email": "profile@test.com",
    "password": "StrongPass1",
}


def get_csrf_headers(client: AsyncClient) -> dict:
    """Extract CSRF token from cookies and return as header dict."""
    token = client.cookies.get("csrf_token")
    if not token:
        return {}
    return {"X-CSRF-Token": token}

@pytest.mark.asyncio
async def test_update_profile(client: AsyncClient):
    # Register and login
    await client.post(f"{BASE}/register", json=VALID_USER, headers=get_csrf_headers(client))
    login_res = await client.post(
        f"{BASE}/login",
        json={"email": VALID_USER["email"], "password": VALID_USER["password"]},
        headers=get_csrf_headers(client),
    )
    token = login_res.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # Update name
    res = await client.patch(
        f"{BASE}/me",
        json={"full_name": "Updated Name"},
        headers={**headers, **get_csrf_headers(client)},
    )
    assert res.status_code == 200
    assert res.json()["full_name"] == "Updated Name"

    # Verify persistence
    res = await client.get(f"{BASE}/me", headers=headers)
    assert res.json()["full_name"] == "Updated Name"

@pytest.mark.asyncio
async def test_update_password(client: AsyncClient):
    # Register
    user = {
        "full_name": "Pass User",
        "email": "pass@test.com",
        "password": "StrongPass1",
    }
    await client.post(f"{BASE}/register", json=user, headers=get_csrf_headers(client))
    login_res = await client.post(
        f"{BASE}/login",
        json={"email": user["email"], "password": user["password"]},
        headers=get_csrf_headers(client),
    )
    token = login_res.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # Update password
    new_pass = "NewStrongPass2"
    res = await client.patch(
        f"{BASE}/me",
        json={"password": new_pass},
        headers={**headers, **get_csrf_headers(client)},
    )
    assert res.status_code == 200
    
    # Verify login with new password
    res = await client.post(
        f"{BASE}/login",
        json={"email": user["email"], "password": new_pass},
        headers=get_csrf_headers(client),
    )
    assert res.status_code == 200

    # Verify old password fails
    res = await client.post(
        f"{BASE}/login",
        json={"email": user["email"], "password": user["password"]},
        headers=get_csrf_headers(client),
    )
    assert res.status_code == 401

@pytest.mark.asyncio
async def test_delete_profile(client: AsyncClient):
    # Register
    user = {
        "full_name": "Delete User",
        "email": "delete@test.com",
        "password": "StrongPass1",
    }
    await client.post(f"{BASE}/register", json=user, headers=get_csrf_headers(client))
    login_res = await client.post(
        f"{BASE}/login",
        json={"email": user["email"], "password": user["password"]},
        headers=get_csrf_headers(client),
    )
    token = login_res.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # Delete
    res = await client.delete(f"{BASE}/me", headers={**headers, **get_csrf_headers(client)})
    assert res.status_code == 200
    assert "deleted" in res.json()["message"]

    # Verify token revoked (or user not found)
    res = await client.get(f"{BASE}/me", headers=headers)
    assert res.status_code == 401

@pytest.mark.asyncio
async def test_security_headers(client: AsyncClient):
    res = await client.get("/")
    assert res.status_code == 200
    assert res.headers["X-Content-Type-Options"] == "nosniff"
    assert res.headers["X-Frame-Options"] == "DENY"
    assert "default-src 'self'" in res.headers["Content-Security-Policy"]
