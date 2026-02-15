import os

# Set test env vars BEFORE any app imports
os.environ["DATABASE_URI"] = "sqlite+aiosqlite://"
os.environ["JWT_SECRET_KEY"] = "test-secret-key-not-for-production"
# Mock Redis to avoid connection errors during import
os.environ["REDIS_URL"] = "redis://mock:6379/0"

from unittest.mock import MagicMock, patch
import sys

class FakeRedis:
    def __init__(self):
        self.data = {}

    async def set(self, key, value, ex=None):
        self.data[key] = value

    async def exists(self, key):
        return 1 if key in self.data else 0

    async def flushdb(self):
        self.data.clear()

    async def close(self):
        pass

# Mock redis module before importing app
mock_redis = MagicMock()
mock_redis.from_url.return_value = FakeRedis()
sys.modules["redis.asyncio"] = mock_redis

import pytest_asyncio  # noqa: E402
from httpx import ASGITransport, AsyncClient  # noqa: E402
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine  # noqa: E402
from sqlmodel import SQLModel  # noqa: E402
from sqlmodel.ext.asyncio.session import AsyncSession  # noqa: E402

from src.auth.blacklist import clear as clear_blacklist  # noqa: E402
from src.auth.models import User  # noqa: F401, E402
from src.auth.controllers import limiter  # noqa: E402
from src.configs.db import get_session  # noqa: E402
from src.main import app  # noqa: E402

# Disable rate limiting during tests
limiter.enabled = False

from sqlalchemy.pool import StaticPool

test_engine = create_async_engine(
    "sqlite+aiosqlite://",
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
test_session_maker = async_sessionmaker(
    test_engine, class_=AsyncSession, expire_on_commit=False
)


async def override_get_session():
    async with test_session_maker() as session:
        yield session


@pytest_asyncio.fixture
async def session():
    async with test_session_maker() as session:
        yield session


app.dependency_overrides[get_session] = override_get_session


@pytest_asyncio.fixture(autouse=True)
async def setup_db():
    """Create all tables before each test, drop after."""
    async with test_engine.begin() as conn:
        await conn.run_sync(SQLModel.metadata.create_all)
    yield
    async with test_engine.begin() as conn:
        await conn.run_sync(SQLModel.metadata.drop_all)
    await clear_blacklist()


@pytest_asyncio.fixture
async def client():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac


@pytest_asyncio.fixture
async def auth_headers(client: AsyncClient) -> dict:
    """Register a user and return auth headers with a valid access token."""
    r = await client.post(
        "/api/v1/auth/register",
        json={
            "full_name": "Test User",
            "email": "fixture@test.com",
            "password": "StrongPass1",
        },
    )
    token = r.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


@pytest_asyncio.fixture(autouse=True)
def mock_celery_task():
    """Mock Celery task to prevent actual broker connection attempts during tests."""
    with patch("src.worker.tasks.send_verification_email.delay") as mock:
        yield mock
