from unittest.mock import patch
from src.worker.tasks import send_verification_email

def test_send_verification_email_task():
    """Test that the task logic runs without error and logs output."""
    with patch("src.worker.tasks.logger") as mock_logger:
        result = send_verification_email("test@example.com", "token123")
        
        assert result is True
        assert mock_logger.info.call_count == 3
        mock_logger.info.assert_any_call("Preparing to send verification email to test@example.com")
