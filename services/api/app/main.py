import logging
from contextlib import asynccontextmanager

import asyncpg
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from redis.asyncio import Redis

from app.core.config import get_settings
from app.core.logging import configure_logging
from app.core.security import SecurityHeadersMiddleware
from app.routers import health, jobs, plugins, webhooks, tactical

settings = get_settings()
logger = logging.getLogger("vexthub.api")


@asynccontextmanager
async def lifespan(app: FastAPI):
    configure_logging()
    app.state.is_mock = False
    
    try:
        app.state.redis = Redis.from_url(settings.redis_url, decode_responses=True)
        # Test redis connection
        await app.state.redis.ping()
    except Exception:
        logger.warning("Redis não encontrado. Iniciando em modo Standalone (Mock Redis).")
        app.state.is_mock = True
        app.state.redis = None

    try:
        app.state.db_pool = await asyncpg.create_pool(
            settings.database_url,
            min_size=1,
            max_size=5,
            timeout=5.0,
        )
    except Exception:
        logger.warning("PostgreSQL não encontrado. Iniciando em modo Standalone (Mock DB).")
        app.state.is_mock = True
        app.state.db_pool = None

    logger.info(f"VextHub API started (Mock Mode: {app.state.is_mock})")
    try:
        yield
    finally:
        if app.state.redis:
            await app.state.redis.aclose()
        if app.state.db_pool:
            await app.state.db_pool.close()
        logger.info("VextHub API stopped")


app = FastAPI(
    title="VextHub API",
    version="4.0.0",
    description="API-first SaaS services for VextHub.",
    lifespan=lifespan,
)

app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "X-Tenant-Id", "X-VextHub-Signature"],
)

@app.get("/", tags=["Root"])
async def root():
    return {
        "service": "VextHub Tactical API",
        "version": "4.0.0",
        "status": "healthy",
        "mode": "standalone" if getattr(app.state, "is_mock", True) else "connected",
        "docs": "/docs",
    }

app.include_router(health.router)
app.include_router(jobs.router)
app.include_router(plugins.router)
app.include_router(webhooks.router)
app.include_router(tactical.router)
