import pytest
from httpx import AsyncClient

BASE = "/api/v1/auth"

VALID_USER = {
    "full_name": "Profile User",
    "email": "profile@test.com",
    "password": "StrongPass1",
}

@pytest.mark.asyncio
async def test_update_profile(client: AsyncClient):
    # Register and login
    await client.post(f"{BASE}/register", json=VALID_USER)
    login_res = await client.post(
        f"{BASE}/login",
        json={"email": VALID_USER["email"], "password": VALID_USER["password"]},
    )
    token = login_res.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # Update name
    res = await client.patch(
        f"{BASE}/me",
        json={"full_name": "Updated Name"},
        headers=headers,
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
    await client.post(f"{BASE}/register", json=user)
    login_res = await client.post(
        f"{BASE}/login",
        json={"email": user["email"], "password": user["password"]},
    )
    token = login_res.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # Update password
    new_pass = "NewStrongPass2"
    res = await client.patch(
        f"{BASE}/me",
        json={"password": new_pass},
        headers=headers,
    )
    assert res.status_code == 200
    
    # Verify login with new password
    res = await client.post(
        f"{BASE}/login",
        json={"email": user["email"], "password": new_pass},
    )
    assert res.status_code == 200

    # Verify old password fails
    res = await client.post(
        f"{BASE}/login",
        json={"email": user["email"], "password": user["password"]},
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
    await client.post(f"{BASE}/register", json=user)
    login_res = await client.post(
        f"{BASE}/login",
        json={"email": user["email"], "password": user["password"]},
    )
    token = login_res.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # Delete
    res = await client.delete(f"{BASE}/me", headers=headers)
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
