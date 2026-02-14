from fastapi import APIRouter, Depends, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from slowapi import Limiter
from slowapi.util import get_remote_address

from src.auth.models import User, UserRole
from src.auth.permissions import RoleChecker
from src.auth.schemas import (
    ChangePasswordRequest,
    LoginRequest,
    MessageResponse,
    RefreshTokenRequest,
    RegisterRequest,
    TokenResponse,
    UserResponse,
    UserUpdateRequest,
)
from src.auth.services import AuthService, get_current_user
from src.configs.config import get_settings
from src.configs.db import SessionDep

settings = get_settings()

limiter = Limiter(key_func=get_remote_address)
bearer_scheme = HTTPBearer()
auth_router = APIRouter(prefix="/auth", tags=["auth"])


@auth_router.post("/register", response_model=TokenResponse)
@limiter.limit(settings.RATE_LIMIT_REGISTER)
async def register(request: Request, body: RegisterRequest, session: SessionDep):
    return await AuthService.register(body, session)


@auth_router.post("/login", response_model=TokenResponse)
@limiter.limit(settings.RATE_LIMIT_LOGIN)
async def login(request: Request, body: LoginRequest, session: SessionDep):
    return await AuthService.login(body, session)


@auth_router.get("/me", response_model=UserResponse)
async def me(user: User = Depends(get_current_user)):
    return user


@auth_router.post("/logout", response_model=MessageResponse)
async def logout(
    credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme),
    _user: User = Depends(get_current_user),
):
    await AuthService.logout(credentials.credentials)
    return {"message": "Successfully logged out"}


@auth_router.post("/refresh", response_model=TokenResponse)
async def refresh(body: RefreshTokenRequest, session: SessionDep):
    return await AuthService.refresh_token(body.refresh_token, session)


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
