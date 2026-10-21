import time

from fastapi import HTTPException, Request
from redis.asyncio import Redis


async def enforce_rate_limit(
    request: Request,
    redis: Redis | None,
    limit: int,
    tenant_id: str = "anonymous",
) -> None:
    if redis is None:
        return

    now = int(time.time())
    window = now // 60
    key = f"rate:{tenant_id}:{request.client.host if request.client else 'unknown'}:{window}"
    count = await redis.incr(key)
    if count == 1:
        await redis.expire(key, 70)
    if count > limit:
        raise HTTPException(status_code=429, detail="Rate limit exceeded")
