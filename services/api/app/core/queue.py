import json
from typing import Any, Dict
from uuid import uuid4

from redis.asyncio import Redis


class JobQueue:
    def __init__(self, redis: Redis):
        self.redis = redis

    async def enqueue(self, tenant_id: str, job_type: str, payload: Dict[str, Any]) -> str:
        job_id = str(uuid4())
        job = {
            "id": job_id,
            "tenant_id": tenant_id,
            "type": job_type,
            "payload": payload,
        }
        await self.redis.lpush("vexthub:jobs", json.dumps(job))
        return job_id
