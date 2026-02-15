from datetime import UTC, datetime, timedelta
from uuid import uuid4

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from starlette.concurrency import run_in_threadpool

from src.configs.config import get_settings

ph = PasswordHasher()
settings = get_settings()



# Pre-computed dummy hash for constant-time login checks
_DUMMY_HASH = ph.hash("dummy-password-for-timing")


async def hash_password(password: str) -> str:
    return await run_in_threadpool(ph.hash, password)


async def verify_password(password: str, hashed_password: str) -> bool:
    def _verify():
        try:
            return ph.verify(hashed_password, password)
        except VerifyMismatchError:
            return False

    return await run_in_threadpool(_verify)


def needs_rehash(hashed_password: str) -> bool:
    return ph.check_needs_rehash(hashed_password)


async def verify_password_dummy() -> None:
    """Burn time equal to a real verify to prevent timing attacks."""
    def _verify_dummy():
        try:
            ph.verify(_DUMMY_HASH, "wrong-password")
        except VerifyMismatchError:
            pass

    await run_in_threadpool(_verify_dummy)


def create_access_token(data: dict) -> str:
    payload = data.copy()
    expire = datetime.now(UTC) + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    payload.update({"exp": expire, "type": "access", "jti": str(uuid4())})
    key = settings.JWT_PRIVATE_KEY if settings.JWT_ALGORITHM.startswith("RS") else settings.JWT_SECRET_KEY
    return jwt.encode(payload, key, algorithm=settings.JWT_ALGORITHM)


def create_refresh_token(data: dict) -> str:
    payload = data.copy()
    expire = datetime.now(UTC) + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
    payload.update({"exp": expire, "type": "refresh", "jti": str(uuid4())})
    key = settings.JWT_PRIVATE_KEY if settings.JWT_ALGORITHM.startswith("RS") else settings.JWT_SECRET_KEY
    return jwt.encode(payload, key, algorithm=settings.JWT_ALGORITHM)


def decode_token(token: str) -> dict:
    key = settings.JWT_PUBLIC_KEY if settings.JWT_ALGORITHM.startswith("RS") else settings.JWT_SECRET_KEY
    return jwt.decode(token, key, algorithms=[settings.JWT_ALGORITHM])
