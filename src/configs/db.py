from typing import Annotated, AsyncGenerator

from fastapi import Depends
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlmodel import SQLModel
from sqlmodel.ext.asyncio.session import AsyncSession

from src.configs.config import get_settings
from src.utils.logger import get_logger

logger = get_logger(__name__)

settings = get_settings()

db_value = settings.DATABASE_URI

if db_value.startswith("sqlite"):
    sqlite_url = db_value
    engine = create_async_engine(
        sqlite_url,
        echo=False,
        future=True,
        connect_args={"check_same_thread": False},
    )
else:
    if db_value.startswith("postgresql+"):
        db_url = db_value
    else:
        db_url = db_value.replace("postgresql://", "postgresql+asyncpg://", 1)
    engine = create_async_engine(
        db_url,
        echo=False,
        future=True,
        pool_size=10,
        max_overflow=20,
        pool_timeout=30,
        pool_pre_ping=True,
    )

async_session_maker = async_sessionmaker(
    engine, class_=AsyncSession, expire_on_commit=False
)


async def create_db_and_tables() -> None:
    try:
        async with engine.begin() as conn:
            await conn.run_sync(SQLModel.metadata.create_all)
        logger.info("Database tables created successfully.")
    except Exception:
        logger.exception("Error creating tables.")
        raise


async def get_session() -> AsyncGenerator[AsyncSession, None]:
    async with async_session_maker() as session:
        yield session


SessionDep = Annotated[AsyncSession, Depends(get_session)]
