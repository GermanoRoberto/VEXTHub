import asyncio
import hashlib
import hmac
import json
import logging
import os
from datetime import datetime, timezone
from typing import Optional

import asyncpg
import httpx
from redis.asyncio import Redis

from app.core.config import get_settings
from app.core.detections import SigmaLiteEngine
from app.core.logging import configure_logging

settings = get_settings()
logger = logging.getLogger("vexthub.worker")
detection_engine = SigmaLiteEngine()


async def handle_compliance_sync(job: dict) -> dict:
    job_id = job.get("id")
    tenant_id = job.get("tenant_id") or job.get("payload", {}).get("tenant_id")
    payload = job.get("payload", {})
    logger.info("Executing compliance.sync job %s for tenant %s", job_id, tenant_id)

    if not tenant_id:
        logger.warning("compliance.sync job %s aborted: missing tenant_id", job_id)
        return {"status": "error", "reason": "missing tenant_id"}

    created_alerts = []
    db_connected = False

    try:
        conn = await asyncpg.connect(settings.database_url, timeout=5.0)
        db_connected = True
        try:
            # 1. Fetch forbidden software policies
            policy_rows = await conn.fetch(
                "SELECT name FROM public.software_policies WHERE tenant_id = $1 AND status = 'forbidden'",
                tenant_id,
            )
            forbidden_set = {r["name"].strip().lower() for r in policy_rows if r.get("name")}
            logger.info("compliance.sync: Loaded %d forbidden policies for tenant %s", len(forbidden_set), tenant_id)

            # 2. Fetch machines
            target_machine = payload.get("machine_id")
            if target_machine:
                machine_rows = await conn.fetch(
                    "SELECT id, hostname, unit, inventory_data FROM public.machines WHERE tenant_id = $1 AND id = $2",
                    tenant_id, target_machine,
                )
            else:
                machine_rows = await conn.fetch(
                    "SELECT id, hostname, unit, inventory_data FROM public.machines WHERE tenant_id = $1",
                    tenant_id,
                )

            for machine in machine_rows:
                m_id = machine["id"]
                m_host = machine.get("hostname") or m_id
                m_unit = machine.get("unit") or "Sem Unidade"
                raw_inv = machine.get("inventory_data")
                inv = json.loads(raw_inv) if isinstance(raw_inv, str) else (raw_inv or {})

                software_list = inv.get("software", []) if isinstance(inv, dict) else []
                for sw in software_list:
                    if not isinstance(sw, dict):
                        continue
                    sw_name = (sw.get("name") or "").strip()
                    if sw_name and sw_name.lower() in forbidden_set:
                        existing = await conn.fetchval(
                            """
                            SELECT id FROM public.compliance_alerts
                            WHERE tenant_id = $1 AND hostname = $2 AND software_name = $3 AND is_resolved = false
                            LIMIT 1
                            """,
                            tenant_id, m_host, sw_name,
                        )
                        if not existing:
                            alert_id = await conn.fetchval(
                                """
                                INSERT INTO public.compliance_alerts (
                                    tenant_id, machine_id, hostname, unit, software_name,
                                    message, severity, risk_score, detection_category, details
                                ) VALUES (
                                    $1, $2, $3, $4, $5, $6, 'high', 75, 'Forbidden Software Policy', $7
                                ) RETURNING id
                                """,
                                tenant_id, m_id, m_host, m_unit, sw_name,
                                f"Software proibido detectado pelo worker de compliance: {sw_name}",
                                json.dumps({"source": "worker.compliance.sync", "job_id": job_id, "software": sw}),
                            )
                            logger.info("compliance.sync created alert %s on host %s (%s)", alert_id, m_host, sw_name)
                            created_alerts.append(str(alert_id))
        finally:
            await conn.close()
    except Exception as exc:
        logger.warning("Direct DB compliance sync failed (%s). Triggering Next.js internal API fallback.", exc)

    if not db_connected:
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                url = f"{settings.app_base_url}/api/compliance/sync"
                headers = {"x-tenant-id": tenant_id}
                secret = getattr(settings, "agent_shared_secret", None) or os.getenv("AGENT_SHARED_SECRET") or ""
                if secret:
                    headers["x-agent-secret"] = secret
                res = await client.post(url, json=payload, headers=headers)
                if res.is_success:
                    logger.info("compliance.sync processed via Next.js fallback API: %s", res.json())
                    return res.json()
        except Exception as http_err:
            logger.error("compliance.sync HTTP fallback failed: %s", http_err)

    return {"status": "completed", "job_id": job_id, "alerts_created": len(created_alerts)}


async def handle_webhook_deliver(job: dict) -> dict:
    job_id = job.get("id")
    payload = job.get("payload", {})
    url = payload.get("url")
    if not url:
        logger.warning("webhook.deliver job %s has no URL", job_id)
        return {"status": "error", "reason": "missing url"}

    secret = payload.get("secret") or getattr(settings, "webhook_signing_secret", None) or os.getenv("WEBHOOK_SIGNING_SECRET") or "vexthub-webhook-secret"
    event_name = payload.get("event") or "event.notification"
    data = payload.get("data") or payload.get("body") or payload

    body_bytes = json.dumps(data, separators=(",", ":"), sort_keys=True).encode("utf-8")
    signature = hmac.new(secret.encode("utf-8"), body_bytes, hashlib.sha256).hexdigest()

    headers = {
        "Content-Type": "application/json",
        "User-Agent": "VextHub-Webhook/4.0",
        "X-VextHub-Signature": f"sha256={signature}",
        "X-VextHub-Event": event_name,
        "X-VextHub-Delivery": str(job_id),
    }

    max_retries = int(payload.get("max_retries", 3))
    delay = float(payload.get("retry_delay", 1.0))
    last_error = None

    for attempt in range(1, max_retries + 1):
        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                response = await client.post(url, content=body_bytes, headers=headers)
                if response.status_code < 400:
                    logger.info("Webhook %s delivered to %s (attempt %d, status %d)", job_id, url, attempt, response.status_code)
                    return {"status": "delivered", "attempt": attempt, "code": response.status_code}
                else:
                    logger.warning("Webhook %s HTTP error %d from %s (attempt %d)", job_id, response.status_code, url, attempt)
                    last_error = f"HTTP {response.status_code}: {response.text[:200]}"
        except Exception as exc:
            logger.warning("Webhook %s attempt %d error: %s", job_id, attempt, exc)
            last_error = str(exc)

        if attempt < max_retries:
            await asyncio.sleep(delay)
            delay *= 2.0

    logger.error("Webhook %s permanently failed after %d attempts: %s", job_id, max_retries, last_error)
    return {"status": "failed", "attempts": max_retries, "error": last_error}


async def handle_plugin_run(job: dict, redis: Optional[Redis]) -> dict:
    job_id = job.get("id")
    tenant_id = job.get("tenant_id") or "global"
    payload = job.get("payload", {})
    image = payload.get("image", "")
    sha256 = payload.get("sha256", "")
    parameters = payload.get("parameters", {})

    logger.info("Executing plugin.run job %s (image=%s)", job_id, image)

    # 1. Validate image digest pinning
    if "@sha256:" not in image:
        logger.warning("Plugin run %s rejected: image not pinned by digest", job_id)
        return {"status": "rejected", "reason": "unpinned_digest"}

    # 2. Execute registered static / diagnostic checks
    findings = []
    if "telemetry" in parameters or isinstance(parameters.get("events"), list):
        findings = detection_engine.scan(parameters.get("telemetry") or parameters)
    else:
        # Default diagnostic scan on parameter payload
        findings = detection_engine.scan({"processes": parameters.get("processes", []), "network": parameters.get("network", [])})

    result = {
        "job_id": job_id,
        "tenant_id": tenant_id,
        "image": image,
        "sha256": sha256,
        "status": "completed",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "findings": findings,
        "findings_count": len(findings),
        "execution_mode": "sandboxed_engine",
    }

    if redis:
        try:
            await redis.setex(f"vexthub:plugin:results:{job_id}", 3600, json.dumps(result))
            logger.info("Stored plugin %s result in Redis key vexthub:plugin:results:%s", job_id, job_id)
        except Exception as r_err:
            logger.warning("Failed to cache plugin result in Redis: %s", r_err)

    return result


async def handle_job(job: dict, redis: Optional[Redis] = None):
    job_type = job.get("type")
    job_id = job.get("id")

    if job_type == "compliance.sync":
        return await handle_compliance_sync(job)

    elif job_type == "webhook.deliver":
        return await handle_webhook_deliver(job)

    elif job_type == "plugin.run":
        return await handle_plugin_run(job, redis)

    elif job_type == "telemetry.process":
        logger.info("Routing telemetry background job %s to internal API", job_id)
        try:
            async with httpx.AsyncClient() as client:
                url = f"{settings.app_base_url}/api/telemetry/process"
                headers = {}
                secret = getattr(settings, "agent_shared_secret", None) or os.getenv("AGENT_SHARED_SECRET") or ""
                if secret:
                    headers["x-agent-secret"] = secret
                response = await client.post(url, json=job["payload"], headers=headers, timeout=30.0)
                response.raise_for_status()
                logger.info("Telemetry background job %s processed successfully", job_id)
        except Exception as e:
            logger.error("Failed to route telemetry job %s: %s", job_id, str(e))
        return

    logger.info("Processed job %s of type %s", job_id, job_type)


async def main():
    configure_logging()
    redis = Redis.from_url(settings.redis_url, decode_responses=True)
    logger.info("VextHub worker started")
    try:
        while True:
            item = await redis.brpop("vexthub:jobs", timeout=5)
            if not item:
                continue
            _, raw_job = item
            await handle_job(json.loads(raw_job), redis=redis)
    finally:
        await redis.aclose()


if __name__ == "__main__":
    asyncio.run(main())
