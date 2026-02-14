import asyncio
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from sqlmodel import text

from src.auth.controllers import auth_router, limiter
from src.configs.config import get_settings
from src.configs.db import SessionDep
from src.utils.logger import get_logger
from src.utils.middleware import RequestIDMiddleware, SecureHeadersMiddleware

logger = get_logger(__name__)
settings = get_settings()


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("App starting")
    yield
    logger.info("App shutting down.")


app = FastAPI(
    title="Auth Service",
    version="1.0.0",
    description="Authentication microservice with JWT-based auth, rate limiting, and request tracing.",
    lifespan=lifespan,
)

# Rate limiter
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# API versioning
app.include_router(auth_router, prefix="/api/v1")

# Middleware (order matters: last added = first executed)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "PUT", "POST", "DELETE", "OPTIONS", "PATCH"],
    allow_headers=["Content-Type", "Authorization"],
)
app.add_middleware(RequestIDMiddleware)
app.add_middleware(SecureHeadersMiddleware)


async def db_is_healthy(session: SessionDep) -> bool:
    try:
        result = await session.exec(text("SELECT 1"))
        _ = result.first()
        return True
    except Exception:
        logger.error("Database health check failed.", exc_info=True)
        return False


@app.get("/", status_code=status.HTTP_200_OK)
async def app_health_check():
    logger.info("Health check endpoint accessed.", extra={"path": "/"})
    return {"status": "Online"}


@app.get("/db-health", status_code=status.HTTP_200_OK)
async def db_health_check(session: SessionDep):
    logger.info("DB health check endpoint accessed.", extra={"path": "/db-health"})
    ok = await db_is_healthy(session)
    if not ok:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="database unreachable",
        )
    return {"status": "ok"}
