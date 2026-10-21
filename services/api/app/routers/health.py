from fastapi import APIRouter, Request

router = APIRouter(prefix="/health", tags=["health"])


@router.get("")
async def health(request: Request):
    checks = {"api": "ok", "postgres": "unknown", "redis": "unknown"}

    try:
        async with request.app.state.db_pool.acquire() as conn:
            await conn.fetchval("select 1")
        checks["postgres"] = "ok"
    except Exception as exc:
        checks["postgres"] = f"error:{type(exc).__name__}"

    try:
        await request.app.state.redis.ping()
        checks["redis"] = "ok"
    except Exception as exc:
        checks["redis"] = f"error:{type(exc).__name__}"

    status = "ok" if all(value == "ok" for value in checks.values()) else "degraded"
    return {"status": status, "checks": checks}
