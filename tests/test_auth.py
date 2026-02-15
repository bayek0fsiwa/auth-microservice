from httpx import AsyncClient

BASE = "/api/v1/auth"

VALID_USER = {
    "full_name": "Test User",
    "email": "test@example.com",
    "password": "StrongPass1",
}


# ── Registration ─────────────────────────────────────────────────────

class TestRegister:
    async def test_register_success(self, client: AsyncClient):
        r = await client.post(f"{BASE}/register", json=VALID_USER)
        assert r.status_code == 200
        data = r.json()
        assert "access_token" in data
        assert "refresh_token" in data
        assert data["token_type"] == "bearer"
        # Check cookies
        assert "access_token" in r.cookies
        assert "refresh_token" in r.cookies

    async def test_register_duplicate_email(self, client: AsyncClient):
        await client.post(f"{BASE}/register", json=VALID_USER)
        r = await client.post(f"{BASE}/register", json=VALID_USER)
        assert r.status_code == 400
        assert "already registered" in r.json()["detail"]

    async def test_register_weak_password(self, client: AsyncClient):
        r = await client.post(
            f"{BASE}/register",
            json={"full_name": "X", "email": "x@test.com", "password": "short"},
        )
        assert r.status_code == 422

    async def test_register_no_uppercase(self, client: AsyncClient):
        r = await client.post(
            f"{BASE}/register",
            json={"full_name": "X", "email": "x@test.com", "password": "nouppercase1"},
        )
        assert r.status_code == 422

    async def test_register_email_normalized(self, client: AsyncClient):
        r = await client.post(
            f"{BASE}/register",
            json={"full_name": "X", "email": "TEST@EXAMPLE.COM", "password": "StrongPass1"},
        )
        assert r.status_code == 200
        # Same email different case should fail
        r2 = await client.post(
            f"{BASE}/register",
            json={"full_name": "Y", "email": "test@example.com", "password": "StrongPass1"},
        )
        assert r2.status_code == 400


# ── Login ────────────────────────────────────────────────────────────

class TestLogin:
    async def test_login_success(self, client: AsyncClient):
        await client.post(f"{BASE}/register", json=VALID_USER)
        r = await client.post(
            f"{BASE}/login",
            json={"email": VALID_USER["email"], "password": VALID_USER["password"]},
        )
        assert r.status_code == 200
        assert "access_token" in r.json()
        # Check cookies
        assert "access_token" in r.cookies
        assert "refresh_token" in r.cookies

    async def test_login_wrong_password(self, client: AsyncClient):
        await client.post(f"{BASE}/register", json=VALID_USER)
        r = await client.post(
            f"{BASE}/login",
            json={"email": VALID_USER["email"], "password": "WrongPass1"},
        )
        assert r.status_code == 401
        assert r.headers.get("WWW-Authenticate") == "Bearer"

    async def test_login_nonexistent_user(self, client: AsyncClient):
        r = await client.post(
            f"{BASE}/login",
            json={"email": "nobody@test.com", "password": "WrongPass1"},
        )
        assert r.status_code == 401
        assert r.headers.get("WWW-Authenticate") == "Bearer"

    async def test_account_lockout(self, client: AsyncClient):
        """After 5 failed logins, account is locked."""
        await client.post(f"{BASE}/register", json=VALID_USER)
        for _ in range(5):
            await client.post(
                f"{BASE}/login",
                json={"email": VALID_USER["email"], "password": "WrongPass1"},
            )
        # 6th attempt should be locked
        r = await client.post(
            f"{BASE}/login",
            json={"email": VALID_USER["email"], "password": "WrongPass1"},
        )
        assert r.status_code == 423
        assert "locked" in r.json()["detail"].lower()

    async def test_lockout_resets_on_success(self, client: AsyncClient):
        """Successful login resets failed attempt counter."""
        await client.post(f"{BASE}/register", json=VALID_USER)
        # 4 failed attempts (below threshold)
        for _ in range(4):
            await client.post(
                f"{BASE}/login",
                json={"email": VALID_USER["email"], "password": "WrongPass1"},
            )
        # Successful login should reset counter
        r = await client.post(
            f"{BASE}/login",
            json={"email": VALID_USER["email"], "password": VALID_USER["password"]},
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
        await client.post(f"{BASE}/register", json=VALID_USER)
        login_res = await client.post(
            f"{BASE}/login",
            json={"email": VALID_USER["email"], "password": VALID_USER["password"]},
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
        reg = await client.post(f"{BASE}/register", json=VALID_USER)
        rt = reg.json()["refresh_token"]
        r = await client.post(f"{BASE}/refresh", json={"refresh_token": rt})
        assert r.status_code == 200
        assert "access_token" in r.json()
        assert "access_token" in r.cookies
        assert "refresh_token" in r.cookies

    async def test_refresh_invalid_token(self, client: AsyncClient):
        r = await client.post(f"{BASE}/refresh", json={"refresh_token": "bad"})
        assert r.status_code == 401

    async def test_refresh_token_rotation(self, client: AsyncClient):
        """After refresh, old refresh token should be blacklisted."""
        reg = await client.post(f"{BASE}/register", json=VALID_USER)
        old_rt = reg.json()["refresh_token"]
        # First refresh succeeds
        r = await client.post(f"{BASE}/refresh", json={"refresh_token": old_rt})
        assert r.status_code == 200
        # Second use of old refresh token should fail (blacklisted)
        r2 = await client.post(f"{BASE}/refresh", json={"refresh_token": old_rt})
        assert r2.status_code == 401
        assert "revoked" in r2.json()["detail"].lower()


# ── Change Password ──────────────────────────────────────────────────

class TestChangePassword:
    async def test_change_password_success(self, client: AsyncClient, auth_headers: dict):
        r = await client.post(
            f"{BASE}/change-password",
            headers=auth_headers,
            json={"old_password": "StrongPass1", "new_password": "NewStrong2"},
        )
        assert r.status_code == 200
        # Login with new password
        r2 = await client.post(
            f"{BASE}/login",
            json={"email": "fixture@test.com", "password": "NewStrong2"},
        )
        assert r2.status_code == 200

    async def test_change_password_wrong_old(self, client: AsyncClient, auth_headers: dict):
        r = await client.post(
            f"{BASE}/change-password",
            headers=auth_headers,
            json={"old_password": "WrongOld1", "new_password": "NewStrong2"},
        )
        assert r.status_code == 400


# ── Logout (Token Blacklisting) ─────────────────────────────────────

class TestLogout:
    async def test_logout(self, client: AsyncClient, auth_headers: dict):
        r = await client.post(f"{BASE}/logout", headers=auth_headers)
        assert r.status_code == 200
        assert r.json()["message"] == "Successfully logged out"

    async def test_token_revoked_after_logout(self, client: AsyncClient, auth_headers: dict):
        """After logout, the access token should be blacklisted."""
        await client.post(f"{BASE}/logout", headers=auth_headers)
        r = await client.get(f"{BASE}/me", headers=auth_headers)
        assert r.status_code == 401
        assert "revoked" in r.json()["detail"].lower()

    async def test_logout_clears_cookies(self, client: AsyncClient):
        # Login to get cookies
        await client.post(f"{BASE}/register", json=VALID_USER)
        await client.post(
            f"{BASE}/login",
            json={"email": VALID_USER["email"], "password": VALID_USER["password"]},
        )
        
        # Logout
        r = await client.post(f"{BASE}/logout")
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
