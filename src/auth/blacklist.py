"""Redis token blacklist with automatic expiry cleanup.

Stores revoked JWT IDs (jti) until they would have expired anyway.
"""

from datetime import UTC, datetime
import redis.asyncio as redis
from src.configs.config import get_settings

settings = get_settings()

redis_client = redis.from_url(settings.REDIS_URL, decode_responses=True)


async def blacklist_token(jti: str, expires_at: datetime) -> None:
    """Add a token's JTI to the blacklist."""
    # Calculate TTL in seconds
    now = datetime.now(UTC)
    ttl = int((expires_at - now).total_seconds())
    if ttl > 0:
        await redis_client.set(jti, "revoked", ex=ttl)


async def is_blacklisted(jti: str) -> bool:
    """Check if a token's JTI is blacklisted."""
    return await redis_client.exists(jti) > 0


async def clear() -> None:
    """Clear the entire blacklist (for testing)."""
    await redis_client.flushdb()
