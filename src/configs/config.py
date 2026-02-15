from functools import lru_cache
from typing import Any

from pydantic import field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    DATABASE_URI: str
    JWT_SECRET_KEY: str  # Kept for backward compatibility or alternate use
    JWT_ALGORITHM: str = "RS256"
    JWT_PRIVATE_KEY: str | None = None
    JWT_PUBLIC_KEY: str | None = None
    JWT_PRIVATE_KEY_PATH: str | None = None
    JWT_PUBLIC_KEY_PATH: str | None = None
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7
    CORS_ORIGINS: list[str] = ["http://localhost:3000"]
    PASSWORD_MIN_LENGTH: int = 8
    ACCOUNT_LOCKOUT_ATTEMPTS: int = 5
    ACCOUNT_LOCKOUT_MINUTES: int = 15
    
    # Rate Limits
    RATE_LIMIT_REGISTER: str = "10/minute"
    RATE_LIMIT_LOGIN: str = "5/minute"

    REDIS_URL: str = "redis://localhost:6379/0"

    # Cookie Settings
    COOKIE_SECURE: bool = False  # Set to True in production (HTTPS)
    COOKIE_SAMESITE: str = "lax"

    # CSRF Settings
    CSRF_COOKIE_NAME: str = "csrf_token"
    CSRF_HEADER_NAME: str = "X-CSRF-Token"
    CSRF_SECRET: str = "csrf-secret-key"  # Change in production



    model_config = SettingsConfigDict(
        env_file=".env", env_file_encoding="utf-8", extra="ignore"
    )

    @field_validator("CORS_ORIGINS", mode="before")
    @classmethod
    def parse_cors_origins(cls, v: Any) -> list[str]:
        if isinstance(v, str) and not v.startswith("["):
            return [origin.strip() for origin in v.split(",")]
        elif isinstance(v, (list, str)):
            return v
        raise ValueError(v)

    @model_validator(mode="after")
    def load_keys_from_path(self) -> "Settings":
        if not self.JWT_PRIVATE_KEY and self.JWT_PRIVATE_KEY_PATH:
            with open(self.JWT_PRIVATE_KEY_PATH, "r") as f:
                self.JWT_PRIVATE_KEY = f.read()
        if not self.JWT_PUBLIC_KEY and self.JWT_PUBLIC_KEY_PATH:
            with open(self.JWT_PUBLIC_KEY_PATH, "r") as f:
                self.JWT_PUBLIC_KEY = f.read()
        return self


@lru_cache()
def get_settings():
    return Settings()  # ty:ignore[missing-argument]