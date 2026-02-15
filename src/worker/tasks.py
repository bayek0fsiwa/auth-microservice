from celery.utils.log import get_task_logger
from src.worker.celery_app import app

logger = get_task_logger(__name__)


@app.task
def send_verification_email(email: str, token: str):
    """
    Simulates sending a verification email.
    In prodcution, this would use SMTP or an email service (SES, SendGrid).
    """
    logger.info(f"Preparing to send verification email to {email}")
    logger.info(f"Verification Link: https://example.com/verify?token={token}")
    logger.info(f"Email sent successfully to {email}")
    return True
