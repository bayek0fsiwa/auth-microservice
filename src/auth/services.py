from datetime import UTC, datetime, timedelta

from typing import Optional

import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession

from src.auth.blacklist import blacklist_token, is_blacklisted
from src.auth.models import User
from src.auth.schemas import (
    ChangePasswordRequest,
    LoginRequest,
    RegisterRequest,
    UserUpdateRequest,
)
from src.auth.security import (
    create_access_token,
    create_refresh_token,
    decode_token,
    hash_password,
    needs_rehash,
    verify_password,
    verify_password_dummy,
)
from src.configs.config import get_settings

settings = get_settings()

_AUTH_HEADER = {"WWW-Authenticate": "Bearer"}
from src.configs.db import get_session
from src.utils.logger import get_logger
from src.worker.tasks import send_verification_email

logger = get_logger(__name__)



class AuthService:
    @staticmethod
    async def register(request: RegisterRequest, session: AsyncSession) -> dict:
        try:
            # Hash password asynchronously before transaction
            hashed_pw = await hash_password(request.password)
            
            user = User(
                full_name=request.full_name,
                email=request.email,
                hashed_password=hashed_pw,
            )
            session.add(user)
            await session.commit()
            try:
                await session.refresh(user)
            except SQLAlchemyError:
                # In high concurrency or test scenarios, refresh might fail but the object is committed.
                # Since id is UUID generated in Python, we can proceed.
                logger.warning("Could not refresh user instance after commit")
        except IntegrityError:
            # Check if it was a duplicate email violation.
            # While we could check existing_user first, relying on DB constraint is safer for race conditions.
            await session.rollback()
            # Double check if it was indeed the email
            statement = select(User).where(User.email == request.email)
            existing = await session.exec(statement)
            if existing.first():
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Email already registered",
                )
            # If not email, it might be something else, re-raise or handle generic
            logger.exception("Database integrity error during registration")
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Service temporarily unavailable",
            )
        except SQLAlchemyError:
            logger.exception("Database error during user creation")
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Service temporarily unavailable",
            )

        logger.info("User registered", extra={"user_id": user.id, "email": user.email})
        
        # Trigger background email task
        # In production, generate a real verification token here
        send_verification_email.delay(user.email, "mock-verification-token")
        
        token_data = {"sub": user.id}
        return {
            "access_token": create_access_token(token_data),
            "refresh_token": create_refresh_token(token_data),
            "token_type": "bearer",
        }

    @staticmethod
    async def login(request: LoginRequest, session: AsyncSession) -> dict:
        try:
            statement = select(User).where(User.email == request.email)
            result = await session.exec(statement)
            user = result.first()
        except SQLAlchemyError:
            logger.exception("Database error during login")
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Service temporarily unavailable",
            )

        if user is None:
            # Constant-time: burn the same time as a real verify
            await verify_password_dummy()
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid email or password",
                headers=_AUTH_HEADER,
            )

        # Check account lockout
        now = datetime.now(UTC)
        if user.locked_until:
            lock_time = user.locked_until
            if lock_time.tzinfo is None:
                lock_time = lock_time.replace(tzinfo=UTC)
            if lock_time > now:
                remaining = int((lock_time - now).total_seconds() // 60) + 1
                raise HTTPException(
                    status_code=status.HTTP_423_LOCKED,
                    detail=f"Account locked. Try again in {remaining} minute(s).",
                )

        if not await verify_password(request.password, user.hashed_password):
            # Increment failed attempts
            try:
                user.failed_login_attempts += 1
                if user.failed_login_attempts >= settings.ACCOUNT_LOCKOUT_ATTEMPTS:
                    user.locked_until = datetime.now(UTC) + timedelta(
                        minutes=settings.ACCOUNT_LOCKOUT_MINUTES
                    )
                    logger.warning(
                        "Account locked due to too many failed attempts",
                        extra={"user_id": user.id, "attempts": user.failed_login_attempts},
                    )
                session.add(user)
                await session.commit()
            except SQLAlchemyError:
                logger.exception("Database error updating failed attempts")

            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid email or password",
                headers=_AUTH_HEADER,
            )

        if not user.is_active:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Account is deactivated",
            )

        # Rehash if argon2 parameters changed
        if needs_rehash(user.hashed_password):
            user.hashed_password = await hash_password(request.password)

        try:
            # Reset lockout on successful login
            user.failed_login_attempts = 0
            user.locked_until = None
            user.last_login = datetime.now(UTC)
            session.add(user)
            await session.commit()
        except SQLAlchemyError:
            logger.exception("Database error updating last_login")

        logger.info("User logged in", extra={"user_id": user.id})
        token_data = {"sub": user.id}
        return {
            "access_token": create_access_token(token_data),
            "refresh_token": create_refresh_token(token_data),
            "token_type": "bearer",
        }

    @staticmethod
    async def logout(token: str) -> None:
        """Blacklist the current access token so it can't be reused."""
        try:
            payload = decode_token(token)
            jti = payload.get("jti")
            exp = datetime.fromtimestamp(payload["exp"], tz=UTC)
            if jti:
                await blacklist_token(jti, exp)
                logger.info("Token blacklisted", extra={"jti": jti})
        except jwt.InvalidTokenError:
            pass  # Token already invalid, nothing to blacklist

    @staticmethod
    async def refresh_token(refresh_token_str: str, session: AsyncSession) -> dict:
        try:
            payload = decode_token(refresh_token_str)
            if payload.get("type") != "refresh":
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid token type",
                    headers=_AUTH_HEADER,
                )
            user_id = payload.get("sub")
            jti = payload.get("jti", "")
        except jwt.ExpiredSignatureError:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Refresh token has expired",
                headers=_AUTH_HEADER,
            )
        except jwt.InvalidTokenError:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid refresh token",
                headers=_AUTH_HEADER,
            )

        # Check if refresh token has been revoked
        if await is_blacklisted(jti):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Refresh token has been revoked",
                headers=_AUTH_HEADER,
            )

        user = await session.get(User, user_id)
        if user is None or not user.is_active:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User not found or inactive",
                headers=_AUTH_HEADER,
            )

        # Blacklist the old refresh token (rotation)
        exp = datetime.fromtimestamp(payload["exp"], tz=UTC)
        await blacklist_token(jti, exp)

        logger.info("Token refreshed", extra={"user_id": user.id})
        token_data = {"sub": user.id}
        return {
            "access_token": create_access_token(token_data),
            "refresh_token": create_refresh_token(token_data),
            "token_type": "bearer",
        }

    @staticmethod
    async def change_password(
        request: ChangePasswordRequest, user: User, session: AsyncSession
    ) -> None:
        if not await verify_password(request.old_password, user.hashed_password):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Current password is incorrect",
            )

        try:
            user.hashed_password = await hash_password(request.new_password)
            user.updated_at = datetime.now(UTC)
            session.add(user)
            await session.commit()
        except SQLAlchemyError:
            logger.exception("Database error during password change")
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Service temporarily unavailable",
            )

        logger.info("Password changed", extra={"user_id": user.id})

    @staticmethod
    async def update_user(
        user: User, request: UserUpdateRequest, session: AsyncSession
    ) -> User:
        if request.email:
            # Check for existing email if changing
            if request.email != user.email:
                statement = select(User).where(User.email == request.email)
                result = await session.exec(statement)
                if result.first():
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail="Email already registered",
                    )
                user.email = request.email

        if request.full_name:
            user.full_name = request.full_name
        
        if request.password:
            user.hashed_password = await hash_password(request.password)

        user.updated_at = datetime.now(UTC)
        try:
            session.add(user)
            await session.commit()
            await session.refresh(user)
        except SQLAlchemyError:
            logger.exception("Database error during profile update")
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Service temporarily unavailable",
            )
        
        logger.info("User profile updated", extra={"user_id": user.id})
        return user

    @staticmethod
    async def delete_user(user: User, token: str, session: AsyncSession) -> None:
        try:
            # Revoke current token
            await AuthService.logout(token)
            
            # Delete user
            await session.delete(user)
            await session.commit()
        except SQLAlchemyError:
            logger.exception("Database error during user deletion")
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Service temporarily unavailable",
            )
        
        logger.info("User deleted", extra={"user_id": user.id})
