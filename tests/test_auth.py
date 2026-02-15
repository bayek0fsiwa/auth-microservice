from httpx import AsyncClient

BASE = "/api/v1/auth"

VALID_USER = {
    "full_name": "Test User",
    "email": "test@example.com",
    "password": "StrongPass1",
}


def get_csrf_headers(client: AsyncClient) -> dict:
    """Extract CSRF token from cookies and return as header dict."""
    token = client.cookies.get("csrf_token")
    if not token:
        return {}
    return {"X-CSRF-Token": token}



# ── Registration ─────────────────────────────────────────────────────

class TestRegister:
    async def test_register_success(self, client: AsyncClient):
        r = await client.post(f"{BASE}/register", json=VALID_USER, headers=get_csrf_headers(client))
        assert r.status_code == 200
        data = r.json()
        assert "access_token" in data
        assert "refresh_token" in data
        assert data["token_type"] == "bearer"
        # Check cookies
        assert "access_token" in r.cookies
        assert "refresh_token" in r.cookies
        assert "csrf_token" in r.cookies

    async def test_register_duplicate_email(self, client: AsyncClient):
        await client.post(f"{BASE}/register", json=VALID_USER, headers=get_csrf_headers(client))
        r = await client.post(f"{BASE}/register", json=VALID_USER, headers=get_csrf_headers(client))
        assert r.status_code == 400
        assert "already registered" in r.json()["detail"]

    async def test_register_weak_password(self, client: AsyncClient):
        r = await client.post(
            f"{BASE}/register",
            json={"full_name": "X", "email": "x@test.com", "password": "short"},
            headers=get_csrf_headers(client),
        )
        assert r.status_code == 422

    async def test_register_no_uppercase(self, client: AsyncClient):
        r = await client.post(
            f"{BASE}/register",
            json={"full_name": "X", "email": "x@test.com", "password": "nouppercase1"},
            headers=get_csrf_headers(client),
        )
        assert r.status_code == 422

    async def test_register_email_normalized(self, client: AsyncClient):
        r = await client.post(
            f"{BASE}/register",
            json={"full_name": "X", "email": "TEST@EXAMPLE.COM", "password": "StrongPass1"},
            headers=get_csrf_headers(client),
        )
        assert r.status_code == 200
        # Same email different case should fail
        r2 = await client.post(
            f"{BASE}/register",
            json={"full_name": "Y", "email": "test@example.com", "password": "StrongPass1"},
            headers=get_csrf_headers(client),
        )
        assert r2.status_code == 400


# ── Login ────────────────────────────────────────────────────────────

class TestLogin:
    async def test_login_success(self, client: AsyncClient):
        await client.post(f"{BASE}/register", json=VALID_USER, headers=get_csrf_headers(client))
        r = await client.post(
            f"{BASE}/login",
            json={"email": VALID_USER["email"], "password": VALID_USER["password"]},
            headers=get_csrf_headers(client),
        )
        assert r.status_code == 200
        assert "access_token" in r.json()
        # Check cookies
        assert "access_token" in r.cookies
        assert "refresh_token" in r.cookies
        assert "csrf_token" in r.cookies

    async def test_login_wrong_password(self, client: AsyncClient):
        await client.post(f"{BASE}/register", json=VALID_USER, headers=get_csrf_headers(client))
        r = await client.post(
            f"{BASE}/login",
            json={"email": VALID_USER["email"], "password": "WrongPass1"},
            headers=get_csrf_headers(client),
        )
        assert r.status_code == 401
        assert r.headers.get("WWW-Authenticate") == "Bearer"

    async def test_login_nonexistent_user(self, client: AsyncClient):
        r = await client.post(
            f"{BASE}/login",
            json={"email": "nobody@test.com", "password": "WrongPass1"},
            headers=get_csrf_headers(client),
        )
        assert r.status_code == 401
        assert r.headers.get("WWW-Authenticate") == "Bearer"

    async def test_account_lockout(self, client: AsyncClient):
        """After 5 failed logins, account is locked."""
        await client.post(f"{BASE}/register", json=VALID_USER, headers=get_csrf_headers(client))
        for _ in range(5):
            await client.post(
                f"{BASE}/login",
                json={"email": VALID_USER["email"], "password": "WrongPass1"},
                headers=get_csrf_headers(client),
            )
        # 6th attempt should be locked
        r = await client.post(
            f"{BASE}/login",
            json={"email": VALID_USER["email"], "password": "WrongPass1"},
            headers=get_csrf_headers(client),
        )
        assert r.status_code == 423
        assert "locked" in r.json()["detail"].lower()

    async def test_lockout_resets_on_success(self, client: AsyncClient):
        """Successful login resets failed attempt counter."""
        await client.post(f"{BASE}/register", json=VALID_USER, headers=get_csrf_headers(client))
        # 4 failed attempts (below threshold)
        for _ in range(4):
            await client.post(
                f"{BASE}/login",
                json={"email": VALID_USER["email"], "password": "WrongPass1"},
                headers=get_csrf_headers(client),
            )
        # Successful login should reset counter
        r = await client.post(
            f"{BASE}/login",
            json={"email": VALID_USER["email"], "password": VALID_USER["password"]},
            headers=get_csrf_headers(client),
        )
        assert r.status_code == 200


# ── Me ───────────────────────────────────────────────────────────────

class TestMe:
    async def test_me_authenticated(self, client: AsyncClient, auth_headers: dict):
        r = await client.get(f"{BASE}/me", headers=auth_headers)
        assert r.status_code == 200
        data = r.json()
        assert data["email"] == "fixture@test.com"
        assert data["role"] == "user"
        assert "X-Request-ID" in r.headers

    async def test_me_unauthenticated(self, client: AsyncClient):
        r = await client.get(f"{BASE}/me")
        assert r.status_code == 401

    async def test_me_invalid_token(self, client: AsyncClient):
        r = await client.get(
            f"{BASE}/me", headers={"Authorization": "Bearer invalidtoken"}
        )
        assert r.status_code == 401
        assert r.headers.get("WWW-Authenticate") == "Bearer"

    async def test_me_cookie_auth(self, client: AsyncClient):
        """Test authentication via cookie (browser flow)."""
        # Register and login to set cookies in client
        await client.post(f"{BASE}/register", json=VALID_USER, headers=get_csrf_headers(client))
        login_res = await client.post(
            f"{BASE}/login",
            json={"email": VALID_USER["email"], "password": VALID_USER["password"]},
            headers=get_csrf_headers(client),
        )
        assert "access_token" in login_res.cookies
        
        # Request /me WITHOUT Authorization header
        # client context handles cookies automatically
        r = await client.get(f"{BASE}/me")
        assert r.status_code == 200
        data = r.json()
        assert data["email"] == VALID_USER["email"]


# ── Refresh ──────────────────────────────────────────────────────────

class TestRefresh:
    async def test_refresh_token(self, client: AsyncClient):
        reg = await client.post(f"{BASE}/register", json=VALID_USER, headers=get_csrf_headers(client))
        rt = reg.json()["refresh_token"]
        r = await client.post(
            f"{BASE}/refresh",
            json={"refresh_token": rt},
            headers=get_csrf_headers(client),
        )
        assert r.status_code == 200
        assert "access_token" in r.json()
        assert "access_token" in r.cookies
        assert "refresh_token" in r.cookies

    async def test_refresh_invalid_token(self, client: AsyncClient):
        # Even for invalid token logical check, CSRF check comes first in middleware
        # So we need a valid CSRF cookie/header pair.
        # Let's hit register just to get a CSRF cookie/token.
        await client.post(f"{BASE}/register", json=VALID_USER, headers=get_csrf_headers(client))
        
        r = await client.post(
            f"{BASE}/refresh",
            json={"refresh_token": "bad"},
            headers=get_csrf_headers(client),
        )
        assert r.status_code == 401

    async def test_refresh_token_rotation(self, client: AsyncClient):
        """After refresh, old refresh token should be blacklisted."""
        reg = await client.post(f"{BASE}/register", json=VALID_USER, headers=get_csrf_headers(client))
        old_rt = reg.json()["refresh_token"]
        # First refresh succeeds
        await client.post(
            f"{BASE}/refresh",
            json={"refresh_token": old_rt},
            headers=get_csrf_headers(client),
        )
        # Second use of old refresh token should fail (blacklisted)
        r2 = await client.post(
            f"{BASE}/refresh",
            json={"refresh_token": old_rt},
            headers=get_csrf_headers(client),
        )
        assert r2.status_code == 401
        assert "revoked" in r2.json()["detail"].lower()


# ── Change Password ──────────────────────────────────────────────────

class TestChangePassword:
    async def test_change_password_success(self, client: AsyncClient, auth_headers: dict):
        # We need to manually add CSRF headers because auth_headers fixture 
        # (if updated) might default them, or we combine them.
        # Note: client.post merges headers.
        
        # Ensure client has cookies from registration in auth_headers fixture?
        # The auth_headers fixture creates a user but might not persist the client cookies 
        # if the client fixture is separate?
        # Actually auth_headers fixture uses the SAME client instance if scope matches.
        # But wait, auth_headers calls client.post("/register"). 
        # So client.cookies should have the CSRF token.
        
        headers = {**auth_headers, **get_csrf_headers(client)}
        
        r = await client.post(
            f"{BASE}/change-password",
            headers=headers,
            json={"old_password": "StrongPass1", "new_password": "NewStrong2"},
        )
        assert r.status_code == 200
        # Login with new password
        r2 = await client.post(
            f"{BASE}/login",
            json={"email": "fixture@test.com", "password": "NewStrong2"},
            headers=get_csrf_headers(client),
        )
        assert r2.status_code == 200

    async def test_change_password_wrong_old(self, client: AsyncClient, auth_headers: dict):
        headers = {**auth_headers, **get_csrf_headers(client)}
        r = await client.post(
            f"{BASE}/change-password",
            headers=headers,
            json={"old_password": "WrongOld1", "new_password": "NewStrong2"},
        )
        assert r.status_code == 400


# ── Logout (Token Blacklisting) ─────────────────────────────────────

class TestLogout:
    async def test_logout(self, client: AsyncClient, auth_headers: dict):
        headers = {**auth_headers, **get_csrf_headers(client)}
        r = await client.post(f"{BASE}/logout", headers=headers)
        assert r.status_code == 200
        assert r.json()["message"] == "Successfully logged out"

    async def test_token_revoked_after_logout(self, client: AsyncClient, auth_headers: dict):
        """After logout, the access token should be blacklisted."""
        headers = {**auth_headers, **get_csrf_headers(client)}
        await client.post(f"{BASE}/logout", headers=headers)
        r = await client.get(f"{BASE}/me", headers=auth_headers)
        assert r.status_code == 401
        assert "revoked" in r.json()["detail"].lower()

    async def test_logout_clears_cookies(self, client: AsyncClient):
        # Login to get cookies
        await client.post(f"{BASE}/register", json=VALID_USER, headers=get_csrf_headers(client))
        await client.post(
            f"{BASE}/login",
            json={"email": VALID_USER["email"], "password": VALID_USER["password"]},
            headers=get_csrf_headers(client),
        )
        
        # Logout
        r = await client.post(f"{BASE}/logout", headers=get_csrf_headers(client))
        assert r.status_code == 200
        
        # Verify cookies are cleared (expired or removed)
        # httpx client.cookies should update on response
        # Asserting that accessing a protected route fails is the best behavioral check.
        
        r_me = await client.get(f"{BASE}/me")
        assert r_me.status_code == 401


# ── Health Checks ────────────────────────────────────────────────────

class TestHealth:
    async def test_health(self, client: AsyncClient):
        r = await client.get("/")
        assert r.status_code == 200
        assert r.json()["status"] == "Online"

    async def test_db_health(self, client: AsyncClient):
        r = await client.get("/db-health")
        assert r.status_code == 200
        assert r.json()["status"] == "ok"


class TestCSRF:
    async def test_csrf_missing(self, client: AsyncClient):
        # Get cookies first
        await client.post(f"{BASE}/register", json=VALID_USER, headers=get_csrf_headers(client))
        # Try POST without header
        r = await client.post(f"{BASE}/refresh", json={"refresh_token": "foo"})
        assert r.status_code == 403
        assert "CSRF token missing" in r.text

    async def test_csrf_mismatch(self, client: AsyncClient):
        await client.post(f"{BASE}/register", json=VALID_USER, headers=get_csrf_headers(client))
        # Try POST with wrong header
        r = await client.post(
            f"{BASE}/refresh",
            json={"refresh_token": "foo"},
            headers={"X-CSRF-Token": "wrong-token"}
        )
        assert r.status_code == 403


from src.auth.models import User
from sqlmodel import select

class TestRBAC:
    async def test_admin_endpoint_forbidden(self, client: AsyncClient, auth_headers: dict):
        # Regular user from auth_headers
        r = await client.get(f"{BASE}/admin/stats", headers=auth_headers)
        assert r.status_code == 403
        
    async def test_admin_endpoint_success(self, client: AsyncClient, session):
        # Create admin user
        admin_data = {"full_name": "Admin", "email": "admin@test.com", "password": "StrongPass1"}
        r = await client.post(f"{BASE}/register", json=admin_data, headers=get_csrf_headers(client))
        assert r.status_code == 200
        
        # Promote to admin in DB
        statement = select(User).where(User.email == "admin@test.com")
        results = await session.exec(statement)
        user = results.first()
        user.role = "admin"
        session.add(user)
        await session.commit()
        
        # Login to get token
        login_res = await client.post(
            f"{BASE}/login",
            json={"email": admin_data["email"], "password": admin_data["password"]},
            headers=get_csrf_headers(client),
        )
        token = login_res.json()["access_token"]
        
        # Access admin endpoint
        r = await client.get(
            f"{BASE}/admin/stats",
            headers={"Authorization": f"Bearer {token}"}
        )
        assert r.status_code == 200
        assert r.json()["message"] == "Admin area"

