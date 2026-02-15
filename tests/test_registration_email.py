import pytest
from unittest.mock import patch
from httpx import AsyncClient


def get_csrf_headers(client: AsyncClient) -> dict:
    """Extract CSRF token from cookies and return as header dict."""
    token = client.cookies.get("csrf_token")
    if not token:
        return {}
    return {"X-CSRF-Token": token}

@pytest.mark.asyncio
async def test_register_triggers_email(client):
    """Verify that registering a user triggers the Celery task."""
    
    # Mock the Celery task
    with patch("src.auth.services.send_verification_email.delay") as mock_delay:
        response = await client.post(
            "/api/v1/auth/register",
            json={
                "email": "newuser@example.com",
                "password": "Password123",
                "full_name": "New User"
            },
            headers=get_csrf_headers(client),
        )
        
        assert response.status_code == 200
        # Verify task was called
        mock_delay.assert_called_once_with("newuser@example.com", "mock-verification-token")
