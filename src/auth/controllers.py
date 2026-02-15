from typing import Optional

from fastapi import APIRouter, Depends, Request, Response
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from slowapi import Limiter
from slowapi.util import get_remote_address

from src.auth.models import User
from src.auth.schemas import (
    ChangePasswordRequest,
    LoginRequest,
    MessageResponse,
    RefreshTokenRequest,
    RegisterRequest,
    TokenResponse,
    UserResponse,
    UserUpdateRequest,
    PublicKeyResponse,
)
from src.auth.dependencies import RoleChecker, get_current_user
from src.auth.services import AuthService
from src.configs.config import get_settings
from src.configs.db import SessionDep
import secrets

settings = get_settings()

limiter = Limiter(key_func=get_remote_address, storage_uri=settings.REDIS_URL)
bearer_scheme = HTTPBearer(auto_error=False)
auth_router = APIRouter(prefix="/auth", tags=["auth"])


@auth_router.post("/register", response_model=TokenResponse)
@limiter.limit(settings.RATE_LIMIT_REGISTER)
async def register(request: Request, response: Response, body: RegisterRequest, session: SessionDep):
    """
    Register a new user.

    - **email**: Valid email address
    - **password**: min 8 chars
    - **full_name**: User's full name
    """
    token_data = await AuthService.register(body, session)
    response.set_cookie(
        key="access_token",
        value=token_data["access_token"],
        httponly=True,
        secure=settings.COOKIE_SECURE,
        samesite=settings.COOKIE_SAMESITE,
    )
    response.set_cookie(
        key="refresh_token",
        value=token_data["refresh_token"],
        httponly=True,
        secure=settings.COOKIE_SECURE,
        samesite=settings.COOKIE_SAMESITE,
    )
    # Set CSRF token (readable by JS)
    csrf_token = secrets.token_urlsafe(32)
    response.set_cookie(
        key=settings.CSRF_COOKIE_NAME,
        value=csrf_token,
        httponly=False,
        secure=settings.COOKIE_SECURE,
        samesite=settings.COOKIE_SAMESITE,
    )
    return token_data


@auth_router.post("/login", response_model=TokenResponse)
@limiter.limit(settings.RATE_LIMIT_LOGIN)
async def login(request: Request, response: Response, body: LoginRequest, session: SessionDep):
    """
    Login with email and password.

    Sets `access_token`, `refresh_token`, and `csrf_token` in HttpOnly/Secure cookies.
    """
    token_data = await AuthService.login(body, session)
    response.set_cookie(
        key="access_token",
        value=token_data["access_token"],
        httponly=True,
        secure=settings.COOKIE_SECURE,
        samesite=settings.COOKIE_SAMESITE,
    )
    response.set_cookie(
        key="refresh_token",
        value=token_data["refresh_token"],
        httponly=True,
        secure=settings.COOKIE_SECURE,
        samesite=settings.COOKIE_SAMESITE,
    )
    # Set CSRF token (readable by JS)
    csrf_token = secrets.token_urlsafe(32)
    response.set_cookie(
        key=settings.CSRF_COOKIE_NAME,
        value=csrf_token,
        httponly=False,
        secure=settings.COOKIE_SECURE,
        samesite=settings.COOKIE_SAMESITE,
    )
    return token_data


@auth_router.get("/me", response_model=UserResponse)
async def me(user: User = Depends(get_current_user)):
    return user


@auth_router.post("/logout", response_model=MessageResponse)
async def logout(
    request: Request,
    response: Response,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme),
):
    token = None
    if credentials:
        token = credentials.credentials
    elif "access_token" in request.cookies:
        token = request.cookies["access_token"]
    
    if token:
        await AuthService.logout(token)
    
    response.delete_cookie("access_token")
    response.delete_cookie("refresh_token")
    response.delete_cookie(settings.CSRF_COOKIE_NAME)
    return {"message": "Successfully logged out"}


@auth_router.post("/refresh", response_model=TokenResponse)
async def refresh(response: Response, body: RefreshTokenRequest, session: SessionDep):
    """
    Refresh an expired access token using a valid refresh token.
    """
    token_data = await AuthService.refresh_token(body.refresh_token, session)
    response.set_cookie(
        key="access_token",
        value=token_data["access_token"],
        httponly=True,
        secure=settings.COOKIE_SECURE,
        samesite=settings.COOKIE_SAMESITE,
    )
    response.set_cookie(
        key="refresh_token",
        value=token_data["refresh_token"],
        httponly=True,
        secure=settings.COOKIE_SECURE,
        samesite=settings.COOKIE_SAMESITE,
    )
    # Rotate CSRF token on refresh
    csrf_token = secrets.token_urlsafe(32)
    response.set_cookie(
        key=settings.CSRF_COOKIE_NAME,
        value=csrf_token,
        httponly=False,
        secure=settings.COOKIE_SECURE,
        samesite=settings.COOKIE_SAMESITE,
    )
    return token_data


@auth_router.post("/change-password", response_model=MessageResponse)
async def change_password(
    body: ChangePasswordRequest,
    session: SessionDep,
    user: User = Depends(get_current_user),
):
    await AuthService.change_password(body, user, session)
    return {"message": "Password changed successfully"}


@auth_router.patch("/me", response_model=UserResponse)
async def update_profile(
    body: UserUpdateRequest,
    session: SessionDep,
    user: User = Depends(get_current_user),
):
    return await AuthService.update_user(user, body, session)


@auth_router.delete("/me", response_model=MessageResponse)
async def delete_profile(
    session: SessionDep,
    credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme),
    user: User = Depends(get_current_user),
):
    await AuthService.delete_user(user, credentials.credentials, session)
    return {"message": "User profile deleted successfully"}


@auth_router.get("/admin/stats", dependencies=[Depends(RoleChecker(["admin"]))])
async def admin_stats():
    return {"message": "Admin area", "stats": "Everything is good"}


@auth_router.get("/public-key", response_model=PublicKeyResponse)
async def get_public_key():
    """
    Get the public key for token verification.

    This endpoint is public and can be used by other microservices to verify JWT signatures.
    """
    if not settings.JWT_PUBLIC_KEY:
        from fastapi import HTTPException
        raise HTTPException(status_code=501, detail="Public key not available (Symmetric keys in use?)")
    
    return {"public_key": settings.JWT_PUBLIC_KEY}

