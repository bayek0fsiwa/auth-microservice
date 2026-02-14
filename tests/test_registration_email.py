import pytest
from unittest.mock import patch

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
        )
        
        assert response.status_code == 200
        # Verify task was called
        mock_delay.assert_called_once_with("newuser@example.com", "mock-verification-token")
