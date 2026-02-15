from datetime import UTC, datetime
from typing import Optional
from uuid import uuid4

from sqlalchemy import Column, DateTime, String
from sqlmodel import Field, SQLModel


from enum import StrEnum

class UserRole(StrEnum):
    USER = "user"
    ADMIN = "admin"


class User(SQLModel, table=True):
    id: str = Field(default_factory=lambda: str(uuid4()), primary_key=True, index=True)
    full_name: str
    email: str = Field(index=True, unique=True)
    hashed_password: str
    role: UserRole = Field(default=UserRole.USER, sa_column=Column(String))
    is_active: bool = Field(default=True)
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
        sa_column=Column(DateTime(timezone=True))
    )
    updated_at: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
        sa_column=Column(DateTime(timezone=True))
    )
    last_login: Optional[datetime] = Field(
        default=None,
        sa_column=Column(DateTime(timezone=True))
    )
    failed_login_attempts: int = Field(default=0)
    locked_until: Optional[datetime] = Field(
        default=None,
        sa_column=Column(DateTime(timezone=True))
    )
