import asyncio
import pytest
from httpx import AsyncClient
from uuid import uuid4

BASE = "/api/v1/auth"

VALID_USER = {
    "full_name": "Concurrent User",
    "email": f"concurrent_{uuid4()}@test.com",
    "password": "StrongPass1",
}

@pytest.mark.asyncio
async def test_register_race_condition(client: AsyncClient):
    """
    Simulate two concurrent registration requests for the same email.
    One should succeed (200), the other should fail (400) handling the integrity error.
    """
    async def register():
        return await client.post(f"{BASE}/register", json=VALID_USER)

    # Run two requests concurrently
    responses = await asyncio.gather(register(), register())
    
    status_codes = [r.status_code for r in responses]
    print(f"Status codes: {status_codes}")
    assert 200 in status_codes
    assert 400 in status_codes
    
    # Verify the failure message
    failure = next(r for r in responses if r.status_code == 400)
    assert "already registered" in failure.json()["detail"]
