import asyncio
import json
import logging
import os
import random
import unicodedata
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

import asyncpg
import httpx
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel

from app.core.auth import TenantContext, require_tenant_context
from app.core.config import get_settings

# Caminho base do projeto
BASE_DIR = Path(__file__).resolve().parent.parent.parent.parent.parent
STATE_FILE = BASE_DIR / "scripts" / "simulation_state.json"
GOVERNANCE_FILE = BASE_DIR / "src" / "data" / "governance-frameworks.json"

router = APIRouter(prefix="/api", tags=["Tactical Tools"])
logger = logging.getLogger("vexthub.tactical")

def simulation_fallback_enabled() -> bool:
    settings = get_settings()
    return (
        os.getenv("VEXTHUB_ENABLE_SIMULATION_FALLBACK", "").lower() == "true"
        or settings.environment.lower() not in {"production", "prod"}
    )

def _json_from_db(value: Any) -> Any:
    if isinstance(value, str):
        try:
            return json.loads(value)
        except Exception:
            return {}
    return value or {}

def _normalize_text(value: str) -> str:
    normalized = unicodedata.normalize("NFD", str(value or "").lower())
    return "".join(char for char in normalized if unicodedata.category(char) != "Mn")

def _load_governance_dataset() -> Dict[str, Any]:
    try:
        with open(GOVERNANCE_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data.get("frameworks"), list):
            return data
    except Exception as exc:
        logger.warning("Governance context unavailable: %s", exc)
    return {"source": {}, "frameworks": []}

def _select_governance_context(message: str, state: Dict[str, Any], limit: int = 6) -> Dict[str, Any]:
    dataset = _load_governance_dataset()
    frameworks = dataset.get("frameworks", [])
    msg = _normalize_text(message)
    events = state.get("events", [])[:80]

    category_hints = set()
    text_blob = msg
    for event in events:
        text_blob += " " + _normalize_text(
            f"{event.get('type', '')} {event.get('description', '')} {json.dumps(event.get('details', {}), ensure_ascii=False)[:500]}"
        )

    if any(term in text_blob for term in ["anydesk", "rustdesk", "remote", "rdp", "acesso remoto"]):
        category_hints.add("remote_access")
    if any(term in text_blob for term in ["persist", "startup", "inicializacao", "run key", "scheduled"]):
        category_hints.add("persistence")
    if any(term in text_blob for term in ["porta", "exposto", "conexao", "tcp", "rede"]):
        category_hints.add("network_exposure")
    if any(term in text_blob for term in ["malware", "trojan", "virus", "quarentena"]):
        category_hints.add("malware_indicator")
    if any(term in text_blob for term in ["politica", "compliance", "governanca", "lgpd", "iso", "cobit", "itil", "controle"]):
        category_hints.add("policy")

    selected = []
    for framework in frameworks:
        score = 2 if framework.get("id") in {"nist-csf", "iso-27001", "cis-controls", "cobit-2019", "itil-4", "itam"} else 0
        finding_categories = set(framework.get("finding_categories") or [])
        score += 4 * len(category_hints.intersection(finding_categories))

        framework_text = _normalize_text(
            " ".join([
                framework.get("id", ""),
                framework.get("name", ""),
                framework.get("category", ""),
                " ".join(framework.get("primary_focus") or []),
                framework.get("prompt_guidance", ""),
            ])
        )
        for token in [item for item in msg.split() if len(item) > 2]:
            if token in framework_text:
                score += 2

        if score > 0:
            selected.append((score, framework))

    selected.sort(key=lambda item: (-item[0], item[1].get("name", "")))
    chosen = []
    for _, framework in selected[:limit]:
        chosen.append({
            "id": framework.get("id"),
            "name": framework.get("name"),
            "category": framework.get("category"),
            "primary_focus": (framework.get("primary_focus") or [])[:5],
            "audit_evidence": (framework.get("audit_evidence") or [])[:5],
            "prompt_guidance": framework.get("prompt_guidance"),
        })

    return {
        "source": dataset.get("source") or {},
        "selected_frameworks": chosen,
        "usage_note": "Use como contexto de governanca para mapear telemetria a controles, evidencias e acoes de gestao; nao afirmar certificacao ou conformidade sem evidencia.",
    }

def _format_governance_context(context: Dict[str, Any]) -> str:
    frameworks = context.get("selected_frameworks") or []
    lines = [
        "Contexto de governanca disponivel:",
        context.get("usage_note", ""),
    ]
    for framework in frameworks:
        lines.append(
            f"- {framework.get('name')}: foco={', '.join(framework.get('primary_focus') or [])}; "
            f"evidencias={', '.join(framework.get('audit_evidence') or [])}; uso={framework.get('prompt_guidance')}"
        )
    return "\n".join(lines)

def _is_real_tenant_id(tenant_id: Optional[str]) -> bool:
    if not tenant_id:
        return False
    val = str(tenant_id).strip()
    if val == "00000000-0000-0000-0000-000000000000":
        return False
    try:
        parsed = uuid.UUID(val)
        return str(parsed) != "00000000-0000-0000-0000-000000000000"
    except (ValueError, AttributeError, TypeError):
        return False

def _to_uuid(val: Any) -> Optional[uuid.UUID]:
    if not val:
        return None
    if isinstance(val, uuid.UUID):
        return val
    try:
        return uuid.UUID(str(val).strip())
    except Exception:
        return None

async def _fetch_db_units(request: Request, tenant_id: Optional[str] = None) -> Optional[List[Dict[str, Any]]]:
    if not _is_real_tenant_id(tenant_id):
        return None
    pool = getattr(request.app.state, "db_pool", None)
    if not pool:
        return None

    try:
        tenant_uuid = _to_uuid(tenant_id)
        query = """
            select id::text, tenant_id::text, name, description, city, state, latitude, longitude,
                   agent_key, auto_allow_compliance, created_at
            from public.units
            where tenant_id = $1
            order by name asc
            limit 500
        """
        rows = await pool.fetch(query, tenant_uuid)
        return [
            {
                "id": row["id"],
                "tenant_id": row["tenant_id"],
                "name": row["name"],
                "description": row["description"] or "",
                "city": row["city"] or "",
                "state": row["state"] or "",
                "lat": row["latitude"],
                "lon": row["longitude"],
                "latitude": row["latitude"],
                "longitude": row["longitude"],
                "agent_key": row["agent_key"],
                "auto_allow_compliance": bool(row["auto_allow_compliance"]),
                "created_at": row["created_at"].isoformat() if row["created_at"] else None,
                "network_assets": [],
            }
            for row in rows
        ]
    except (asyncpg.PostgresError, OSError, asyncio.TimeoutError) as exc:
        logger.warning(f"PostgreSQL error fetching units: {exc}")
        return None
    except Exception as exc:
        logger.error(f"Unexpected error fetching units from DB: {exc}")
        return None

async def _fetch_db_machines(
    request: Request,
    unit_id: Optional[str] = None,
    tenant_id: Optional[str] = None
) -> Optional[List[Dict[str, Any]]]:
    if not _is_real_tenant_id(tenant_id):
        return None
    pool = getattr(request.app.state, "db_pool", None)
    if not pool:
        return None

    try:
        tenant_uuid = _to_uuid(tenant_id)
        params: List[Any] = [tenant_uuid]
        where_clauses = ["tenant_id = $1"]
        if unit_id:
            params.append(unit_id)
            where_clauses.append(f"(unit = ${len(params)} or unit_id::text = ${len(params)})")

        query = f"""
            select id, tenant_id::text, unit_id::text, hostname, serial_number, unit, os_name, cpu_info,
                   ram_total, agent_version, inventory_data::text as inventory_data, last_pulse
            from public.machines
            where {" and ".join(where_clauses)}
            order by last_pulse desc nulls last
            limit 500
        """
        rows = await pool.fetch(query, *params)
        return [
            {
                "id": row["id"],
                "tenant_id": row["tenant_id"],
                "unit_id": row["unit_id"],
                "hostname": row["hostname"] or "UNKNOWN",
                "serial_number": row["serial_number"] or "",
                "unit": row["unit"] or "UN-00",
                "os_name": row["os_name"] or "",
                "cpu_info": row["cpu_info"] or "",
                "ram_total": row["ram_total"] or "",
                "agent_version": row["agent_version"] or "",
                "inventory_data": _json_from_db(row["inventory_data"]),
                "last_pulse": row["last_pulse"].isoformat() if row["last_pulse"] else None,
                "status": "online" if row["last_pulse"] else "offline",
            }
            for row in rows
        ]
    except (asyncpg.PostgresError, OSError, asyncio.TimeoutError) as exc:
        logger.warning(f"PostgreSQL error fetching machines: {exc}")
        return None
    except Exception as exc:
        logger.error(f"Unexpected error fetching machines from DB: {exc}")
        return None

async def _fetch_db_alerts(
    request: Request,
    tenant_id: Optional[str] = None,
    limit: int = 500
) -> Optional[List[Dict[str, Any]]]:
    if not _is_real_tenant_id(tenant_id):
        return None
    pool = getattr(request.app.state, "db_pool", None)
    if not pool:
        return None

    try:
        tenant_uuid = _to_uuid(tenant_id)
        query = """
            select id::text, tenant_id::text, machine_id, hostname, unit, software_name,
                   message, severity, risk_score, detection_category,
                   details::text as details, created_at, is_resolved
            from public.compliance_alerts
            where tenant_id = $1
            order by created_at desc
            limit $2
        """
        rows = await pool.fetch(query, tenant_uuid, limit)
        return [
            {
                "id": row["id"],
                "tenant_id": row["tenant_id"],
                "machine_id": row["machine_id"],
                "machine": row["machine_id"] or row["hostname"] or "GLOBAL",
                "hostname": row["hostname"],
                "unit": row["unit"],
                "software_name": row["software_name"],
                "message": row["message"],
                "description": row["message"],
                "severity": (row["severity"] or "medium").lower(),
                "risk_score": row["risk_score"] or 0,
                "detection_category": row["detection_category"] or "compliance",
                "type": row["detection_category"] or "COMPLIANCE_ALERT",
                "details": _json_from_db(row["details"]),
                "created_at": row["created_at"].isoformat() if row["created_at"] else None,
                "timestamp": row["created_at"].isoformat() if row["created_at"] else None,
                "is_resolved": bool(row["is_resolved"]),
            }
            for row in rows
        ]
    except (asyncpg.PostgresError, OSError, asyncio.TimeoutError) as exc:
        logger.warning(f"PostgreSQL error fetching compliance alerts: {exc}")
        return None
    except Exception as exc:
        logger.error(f"Unexpected error fetching compliance alerts from DB: {exc}")
        return None

async def _fetch_db_commands(
    request: Request,
    tenant_id: Optional[str] = None,
    machine_id: Optional[str] = None,
    limit: int = 100
) -> Optional[List[Dict[str, Any]]]:
    if not _is_real_tenant_id(tenant_id):
        return None
    pool = getattr(request.app.state, "db_pool", None)
    if not pool:
        return None

    try:
        tenant_uuid = _to_uuid(tenant_id)
        params: List[Any] = [tenant_uuid]
        where_clauses = ["tenant_id = $1"]
        if machine_id:
            params.append(machine_id)
            where_clauses.append(f"machine_id = ${len(params)}")

        params.append(limit)
        query = f"""
            select id::text, tenant_id::text, machine_id, command_type, target, status, result,
                   created_at, updated_at
            from public.agent_commands
            where {" and ".join(where_clauses)}
            order by created_at desc
            limit ${len(params)}
        """
        rows = await pool.fetch(query, *params)
        return [
            {
                "id": row["id"],
                "tenant_id": row["tenant_id"],
                "machine_id": row["machine_id"],
                "command_type": row["command_type"],
                "target": row["target"],
                "status": row["status"],
                "result": row["result"],
                "created_at": row["created_at"].isoformat() if row["created_at"] else None,
                "updated_at": row["updated_at"].isoformat() if row["updated_at"] else None,
            }
            for row in rows
        ]
    except (asyncpg.PostgresError, OSError, asyncio.TimeoutError) as exc:
        logger.warning(f"PostgreSQL error fetching agent commands: {exc}")
        return None
    except Exception as exc:
        logger.error(f"Unexpected error fetching agent commands from DB: {exc}")
        return None

async def _insert_db_command(
    request: Request,
    tenant_id: str,
    machine_id: str,
    command_type: str,
    target: Optional[str] = None
) -> Optional[str]:
    if not _is_real_tenant_id(tenant_id):
        return None
    pool = getattr(request.app.state, "db_pool", None)
    if not pool:
        return None

    try:
        tenant_uuid = _to_uuid(tenant_id)
        query = """
            insert into public.agent_commands (tenant_id, machine_id, command_type, target, status)
            values ($1, $2, $3, $4, 'pending')
            returning id::text
        """
        cmd_id = await pool.fetchval(query, tenant_uuid, machine_id, command_type, target)
        return str(cmd_id) if cmd_id else None
    except (asyncpg.PostgresError, OSError, asyncio.TimeoutError) as exc:
        logger.warning(f"PostgreSQL error inserting agent command: {exc}")
        return None
    except Exception as exc:
        logger.error(f"Unexpected error inserting agent command in DB: {exc}")
        return None

async def _insert_db_audit_log(
    request: Request,
    tenant_id: str,
    action: str,
    target_type: str,
    target_id: Optional[str] = None,
    details: Optional[Dict[str, Any]] = None
) -> Optional[str]:
    if not _is_real_tenant_id(tenant_id):
        return None
    pool = getattr(request.app.state, "db_pool", None)
    if not pool:
        return None

    try:
        tenant_uuid = _to_uuid(tenant_id)
        details_json = json.dumps(details or {})
        query = """
            insert into public.audit_log (tenant_id, action, target_type, target_id, details)
            values ($1, $2, $3, $4, $5::jsonb)
            returning id::text
        """
        audit_id = await pool.fetchval(query, tenant_uuid, action, target_type, target_id, details_json)
        return str(audit_id) if audit_id else None
    except (asyncpg.PostgresError, OSError, asyncio.TimeoutError) as exc:
        logger.warning(f"PostgreSQL error inserting audit log: {exc}")
        return None
    except Exception as exc:
        logger.error(f"Unexpected error inserting audit log in DB: {exc}")
        return None

PLAYBOOK_COMMAND_MAP = {
    "software_inventory": "REFRESH_INVENTORY",
    "network_census": "REFRESH_INVENTORY",
    "forensic_snapshot": "RUN_COMPLIANCE_SCAN",
    "integrity_audit": "RUN_COMPLIANCE_SCAN",
    "soft_isolation": "RUN_COMPLIANCE_SCAN",
}

class NeuralChatRequest(BaseModel):
    message: str
    context_level: str = "balanced"

class NeuralChatResponse(BaseModel):
    response: str
    model: str
    engine_status: str
    engine_provider: Optional[str] = None
    degraded_reason: Optional[str] = None
    suggested_playbooks: List[str] = []
    tactical_context: Dict[str, Any] = {}

class PlaybookCatalogItem(BaseModel):
    id: str
    label: str
    category: str
    description: str
    scope: List[str]

@router.get("/playbooks/catalog", response_model=List[PlaybookCatalogItem])
async def get_playbook_catalog(tenant: TenantContext = Depends(require_tenant_context)):
    return [
        {"id": "software_inventory", "label": "Inventário de Software", "category": "Inventário", "description": "Atualiza o inventário de programas, versões e evidências de risco.", "scope": ["all", "agent"]},
        {"id": "network_census", "label": "Censo de Rede", "category": "Rede", "description": "Consolida interfaces, IPs e ativos relacionados à unidade.", "scope": ["all", "agent"]},
        {"id": "forensic_snapshot", "label": "Snapshot Forense", "category": "Forense", "description": "Registra processos, conexões e eventos recentes para triagem defensiva.", "scope": ["all", "agent"]},
        {"id": "integrity_audit", "label": "Auditoria de Integridade", "category": "Segurança", "description": "Revalida postura do endpoint contra políticas e alertas conhecidos.", "scope": ["agent"]},
        {"id": "soft_isolation", "label": "Quarentena Inteligente", "category": "Segurança", "description": "Isola o endpoint bloqueando todo o tráfego de rede (Wi-Fi/Cabo) via Firewall nativo, mas preserva túneis de RDP para a TI e comunicação essencial com a VextHub.", "scope": ["agent"]},
    ]

class PlaybookExecuteRequest(BaseModel):
    playbook_id: str
    machine_id: Optional[str] = None
    scope: str = "all"

@router.post("/playbooks/execute")
async def execute_playbook(
    payload: PlaybookExecuteRequest,
    request: Request,
    tenant: TenantContext = Depends(require_tenant_context)
):
    logger.info(f"Executando playbook {payload.playbook_id} no escopo {payload.scope} (tenant: {tenant.tenant_id})")

    # Mode A: When real tenant and db_pool active, insert commands into public.agent_commands and record in public.audit_log
    if _is_real_tenant_id(tenant.tenant_id):
        pool = getattr(request.app.state, "db_pool", None)
        if pool:
            try:
                cmd_type = PLAYBOOK_COMMAND_MAP.get(payload.playbook_id, "RUN_COMPLIANCE_SCAN")
                target_machines: List[str] = []
                if payload.machine_id and payload.machine_id not in ("GLOBAL", "all", ""):
                    target_machines.append(payload.machine_id)
                else:
                    m_rows = await pool.fetch(
                        "select id from public.machines where tenant_id = $1 limit 50",
                        _to_uuid(tenant.tenant_id)
                    )
                    target_machines = [r["id"] for r in m_rows]
                    if not target_machines:
                        target_machines = [payload.machine_id or "GLOBAL"]

                created_commands: List[str] = []
                for mid in target_machines:
                    cmd_id = await _insert_db_command(
                        request,
                        tenant.tenant_id,
                        mid,
                        cmd_type,
                        target=payload.playbook_id
                    )
                    if cmd_id:
                        created_commands.append(cmd_id)

                await _insert_db_audit_log(
                    request,
                    tenant.tenant_id,
                    action="PLAYBOOK_EXECUTE",
                    target_type="playbook",
                    target_id=payload.playbook_id,
                    details={
                        "playbook_id": payload.playbook_id,
                        "scope": payload.scope,
                        "machine_id": payload.machine_id,
                        "commands_enqueued": len(created_commands),
                    }
                )

                if created_commands:
                    return {
                        "status": "success",
                        "event_id": f"CMD-{created_commands[0]}",
                        "commands": created_commands,
                        "enqueued_count": len(created_commands)
                    }
            except (asyncpg.PostgresError, OSError, asyncio.TimeoutError) as exc:
                logger.warning(f"PostgreSQL playbook execution failed, falling back to simulation state: {exc}")
            except Exception as exc:
                logger.error(f"Unexpected error in DB playbook execution: {exc}")

    # Mode B: Fallback to simulation_state.json
    if simulation_fallback_enabled() and STATE_FILE.exists():
        try:
            with open(STATE_FILE, "r", encoding="utf-8") as f:
                state = json.load(f)

            details_payload = {
                "playbook": payload.playbook_id,
                "operator": "VEXT-AI-CORTEX",
                "status": "COMPLETED",
                "execution_time_ms": random.randint(450, 2300)
            }

            if payload.playbook_id == "network_census":
                details_payload["network_discovery"] = {
                    "scanned_subnets": ["10.0.1.0/24", "10.0.2.0/24", "192.168.100.0/24"],
                    "active_hosts": random.randint(450, 890),
                    "rogue_devices_detected": random.randint(0, 5),
                    "open_ports_summary": {"tcp/445": 145, "tcp/3389": 22, "tcp/22": 8, "tcp/80": 67},
                    "dns_anomalies": ["tunnel.hacker.net", "crypto-pool.org"],
                    "arp_spoofing_detected": False
                }
            elif payload.playbook_id == "software_inventory":
                details_payload["software_audit"] = {
                    "total_installed_packages": random.randint(12000, 15000),
                    "unauthorized_apps_found": ["RustDesk", "AnyDesk", "BitTorrent", "Steam"],
                    "outdated_critical_apps": ["Google Chrome < 120", "Java 8 Update 201", "WinRAR 5.40"],
                    "compliance_score_avg": "74%",
                    "high_risk_endpoints": random.randint(12, 45)
                }
            elif payload.playbook_id == "forensic_snapshot":
                details_payload["forensic_data"] = {
                    "total_running_processes": random.randint(4000, 6000),
                    "suspicious_processes": ["powershell.exe -ExecutionPolicy Bypass -enc...", "svchost.exe (Orphaned)"],
                    "active_tcp_connections": random.randint(1500, 3000),
                    "external_malicious_ips": ["185.15.22.1 (RU)", "45.10.11.2 (CN)"],
                    "registry_modifications": ["HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Payload"],
                    "memory_dump_status": "Archived"
                }
            elif payload.playbook_id == "soft_isolation":
                details_payload["isolation_status"] = {
                    "firewall_rules_applied": 24,
                    "traffic_blocked": "ALL_OUTBOUND_INBOUND",
                    "exceptions_allowed": ["VextHub-API (TCP 8000)", "IT-RDP-Subnet (10.1.1.0/24)"],
                    "active_connections_killed": random.randint(80, 200),
                    "machine_state": "ISOLATED_BUT_REACHABLE"
                }

            new_event = {
                "id": f"EVT-{random.randint(1000, 9999)}",
                "timestamp": datetime.now().isoformat(),
                "machine": payload.machine_id or "GLOBAL",
                "type": "PLAYBOOK_EXECUTION",
                "severity": "info",
                "description": f"Execução defensiva do playbook {payload.playbook_id} completada com sucesso. Resultados anexados ao dump.",
                "details": details_payload
            }

            if "events" not in state:
                state["events"] = []

            state["events"].insert(0, new_event)

            with open(STATE_FILE, "w", encoding="utf-8") as f:
                json.dump(state, f, indent=2)

            return {"status": "success", "event_id": new_event["id"]}
        except Exception as e:
            logger.error(f"Erro ao salvar evento: {e}")
            raise HTTPException(status_code=500, detail="Erro ao persistir execução")

    return {"status": "enqueued", "id": payload.playbook_id}

SYSTEM_PROMPT_CORTEX = """
Voce e o Cortex Neural, o assistente defensivo de SOC e resposta a incidentes do VextHub.
Seu trabalho e transformar telemetria de endpoints, inventario, eventos e fila de comandos em orientacao operacional clara.

Diretrizes de Resposta:
1. Responda sempre em Portugues do Brasil.
2. Seja direto, especifico e util para um operador SOC.
3. Nao invente fatos sobre a rede quando nao houver dados.
4. Diferencie observacao, hipotese e proxima acao.
5. Recomende somente acoes defensivas permitidas: inventario, compliance, atualizacao de agente, triagem forense e revisao de alertas.
6. Evite jargao vazio ou promessas de execucao privilegiada.
7. Mantenha as respostas curtas, com prioridade, motivo e proximo passo.
8. Quando houver contexto de governanca, conecte alertas a frameworks, controles e evidencias auditaveis sem afirmar conformidade ou certificacao sem prova.
"""

@router.post("/neural/chat", response_model=NeuralChatResponse)
async def neural_chat(
    payload: NeuralChatRequest,
    request: Request,
    tenant: TenantContext = Depends(require_tenant_context)
):
    msg = payload.message.lower()
    api_key = os.getenv("OPENAI_API_KEY") or os.getenv("VEXTHUB_AI_API_KEY")

    # Mode A: Real tenant live metrics from PostgreSQL
    db_metrics_available = False
    db_machines_count = 0
    db_units_count = 0
    db_pending_commands_count = 0
    db_events: List[Dict[str, Any]] = []

    if _is_real_tenant_id(tenant.tenant_id):
        pool = getattr(request.app.state, "db_pool", None)
        if pool:
            try:
                t_uuid = _to_uuid(tenant.tenant_id)
                db_machines_count = await pool.fetchval("select count(*) from public.machines where tenant_id = $1", t_uuid) or 0
                db_units_count = await pool.fetchval("select count(*) from public.units where tenant_id = $1", t_uuid) or 0
                db_pending_commands_count = await pool.fetchval("select count(*) from public.agent_commands where tenant_id = $1 and status = 'pending'", t_uuid) or 0
                alerts = await _fetch_db_alerts(request, tenant.tenant_id, limit=50)
                db_events = alerts or []
                db_metrics_available = True
            except (asyncpg.PostgresError, OSError, asyncio.TimeoutError) as exc:
                logger.warning(f"Failed to fetch live PostgreSQL metrics for neural chat: {exc}")
            except Exception as exc:
                logger.error(f"Unexpected error fetching DB neural context: {exc}")

    # Mode B: Fallback to simulation state
    if simulation_fallback_enabled():
        try:
            with open(STATE_FILE, "r", encoding="utf-8") as f:
                state = json.load(f)
        except Exception:
            state = {"machines": [], "units": [], "events": [], "agent_commands": []}
    else:
        state = {"machines": [], "units": [], "events": [], "agent_commands": []}

    governance_context = _select_governance_context(payload.message, state)
    governance_prompt = _format_governance_context(governance_context)

    # Se houver chave de API, tenta usar integração real
    if api_key:
        try:
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    "https://api.openai.com/v1/chat/completions",
                    headers={"Authorization": f"Bearer {api_key}"},
                    json={
                        "model": "gpt-4o-mini",
                        "messages": [
                            {"role": "system", "content": f"{SYSTEM_PROMPT_CORTEX}\n\n{governance_prompt}"},
                            {"role": "user", "content": payload.message}
                        ],
                        "temperature": 0.7
                    },
                    timeout=30.0
                )
                if response.status_code == 200:
                    data = response.json()
                    ai_text = data["choices"][0]["message"]["content"]
                    return NeuralChatResponse(
                        response=ai_text,
                        model="Cortex-Neural-Defensive-H1",
                        engine_status="provider_active",
                        engine_provider="openai_provider",
                        suggested_playbooks=["forensic_snapshot"],
                        tactical_context={
                            "insight_cards": [
                                {"title": "Modo", "value": "API Ativa", "detail": "Provedor externo conectado", "tone": "accent"},
                                {"title": "Postura", "value": "Defensiva", "detail": "Acoes por allowlist", "tone": "neural"},
                                {"title": "Governanca", "value": str(len(governance_context.get("selected_frameworks", []))), "detail": "Frameworks no contexto", "tone": "warning"}
                            ],
                            "governance_context": governance_context
                        }
                    )
        except Exception as e:
            logger.error(f"Erro na integração AI: {e}")

    if db_metrics_available:
        machines_count = db_machines_count
        units_count = db_units_count
        events = db_events
        high_events = [e for e in events if str(e.get("severity", "")).upper() in {"HIGH", "CRITICAL"}]
        pending_commands_count = db_pending_commands_count
        fleet_detail = "Endpoints em produção"
    else:
        machines_count = len(state.get("machines", []))
        units_count = len(state.get("units", []))
        events = state.get("events", [])
        high_events = [e for e in events if str(e.get("severity", "")).upper() in {"HIGH", "CRITICAL"}]
        pending_commands = [c for c in state.get("agent_commands", []) if c.get("status") == "pending"]
        pending_commands_count = len(pending_commands)
        fleet_detail = "Endpoints no simulador"

    latest_event = events[0] if events else None

    if "entropia" in msg or "exfiltração" in msg or "exfiltracao" in msg or "vulnerabilidade" in msg:
        response_text = (
            f"Contexto atual: {machines_count} endpoints ({fleet_detail.lower()}), {len(high_events)} eventos HIGH/CRITICAL e "
            f"{pending_commands_count} comandos pendentes. Nao ha captura de fluxo suficiente para afirmar exfiltracao. "
            "Hipotese prioritaria: validar endpoints com alerta recente e software remoto suspeito. "
            "Proximo passo: execute Snapshot Forense no endpoint afetado e revalide compliance antes de qualquer contencao."
        )
        insight_tone = "danger"
    elif "unidade" in msg or "un-01" in msg or "un-02" in msg:
        unit_id = "UN-01/UN-02" if "02" in msg else "UN-01"
        unit_machines = [m for m in state.get("machines", []) if m.get("unit") in unit_id.split("/")]
        unit_events = [e for e in events if e.get("unit") in unit_id.split("/")]
        response_text = (
            f"Unidade {unit_id}: encontrei {len(unit_machines)} endpoints e {len(unit_events)} eventos associados. "
            "Observacao: use a tela de dispositivos para abrir um host especifico antes de disparar comandos. "
            "Proximo passo recomendado: Atualizar inventario em um endpoint representativo e revisar os alertas recentes da unidade."
        )
        insight_tone = "warning"
    elif any(term in msg for term in ["governanca", "governança", "framework", "iso", "cobit", "itil", "lgpd", "compliance", "controle"]):
        selected_frameworks = governance_context.get("selected_frameworks", [])
        framework_names = ", ".join([str(item.get("name")) for item in selected_frameworks[:5]]) or "NIST CSF, ISO 27001 e CIS Controls"
        first_framework = selected_frameworks[0] if selected_frameworks else {}
        evidence = ", ".join(first_framework.get("audit_evidence", [])[:4]) if first_framework else "inventario, alertas, logs e acoes corretivas"
        response_text = (
            f"Contexto de governanca carregado: {framework_names}. "
            f"Para o estado atual ({machines_count} endpoints e {len(high_events)} eventos HIGH/CRITICAL), a IA deve mapear cada alerta para controles, evidencias e dono do risco. "
            f"Evidencias prioritarias: {evidence}. "
            "Proximo passo: escolha um alerta ou unidade para eu devolver o mapeamento controle -> evidencia -> acao."
        )
        insight_tone = "warning"
    elif "segurança" in msg or "seguranca" in msg or "ameaça" in msg or "ameaca" in msg or "ataque" in msg or "alerta" in msg:
        event_text = "sem evento recente" if not latest_event else f"{latest_event.get('type')} em {latest_event.get('agent_hostname') or latest_event.get('machine')}"
        response_text = (
            f"Triagem de seguranca: {event_text}. "
            f"Ha {len(high_events)} eventos de alta criticidade no buffer. "
            "Prioridade: confirmar se o endpoint ainda esta online, atualizar inventario e executar revalidacao de compliance. "
            "Se o mesmo software remoto aparecer em mais de uma unidade, abra relatorio por unidade antes de escalar."
        )
        insight_tone = "danger"
    elif "ajuda" in msg or "como" in msg or "capacidades" in msg:
        response_text = (
            "Posso ajudar em quatro frentes: resumir risco por unidade, explicar eventos recentes, "
            "sugerir playbooks defensivos e orientar comandos seguros do agente. "
            "Comandos permitidos: atualizar inventario, revalidar compliance e sincronizar agente. "
            "Para uma acao concreta, informe unidade, hostname ou software."
        )
        insight_tone = "neural"
    elif "inventário" in msg or "inventario" in msg or "máquina" in msg or "maquina" in msg or "dispositivo" in msg:
        response_text = (
            f"Inventario disponivel: {machines_count} endpoints distribuidos em {units_count} unidades. "
            f"A tela de dispositivos carrega uma amostra operacional e permite abrir cada host para software, hardware, historico e fila do agente. "
            "Proximo passo: escolha um hostname e acione Atualizar inventario para confirmar recebimento no proximo pulso."
        )
        insight_tone = "accent"
    else:
        response_text = (
            f"Contexto carregado: {machines_count} endpoints, {units_count} unidades, {len(events)} eventos e "
            f"{pending_commands_count} comandos pendentes. "
            "Pergunte por uma unidade, um hostname, inventario ou alertas para eu devolver uma recomendacao operacional objetiva."
        )
        insight_tone = "neutral"

    return NeuralChatResponse(
        response=response_text,
        model="VEXT-Cortex-Neural-Local",
        engine_status="ready",
        engine_provider="postgresql_live" if db_metrics_available else "local_simulation_heuristic",
        suggested_playbooks=["forensic_snapshot", "software_inventory"],
        tactical_context={
            "insight_cards": [
                {"title": "Frota", "value": str(machines_count), "detail": fleet_detail, "tone": "accent"},
                {"title": "Alertas", "value": str(len(high_events)), "detail": "Eventos HIGH/CRITICAL", "tone": insight_tone},
                {"title": "Fila", "value": str(pending_commands_count), "detail": "Comandos pendentes", "tone": "neural"},
                {"title": "Governanca", "value": str(len(governance_context.get("selected_frameworks", []))), "detail": "Frameworks no contexto", "tone": "warning"}
            ],
            "governance_context": governance_context
        }
    )


@router.get("/forensics/events")
async def get_forensic_events(
    request: Request,
    tenant_id: Optional[str] = None,
    tenant: TenantContext = Depends(require_tenant_context)
):
    effective_tenant = tenant.tenant_id if _is_real_tenant_id(tenant.tenant_id) else tenant_id
    if _is_real_tenant_id(effective_tenant):
        alerts = await _fetch_db_alerts(request, effective_tenant, limit=200)
        if alerts is not None:
            return [
                {
                    "id": a["id"],
                    "timestamp": a.get("created_at") or a.get("timestamp") or datetime.now().isoformat(),
                    "machine": a.get("machine_id") or a.get("hostname") or "GLOBAL",
                    "agent_hostname": a.get("hostname"),
                    "unit": a.get("unit"),
                    "type": a.get("detection_category") or "COMPLIANCE_ALERT",
                    "severity": str(a.get("severity") or "medium").upper(),
                    "description": a.get("message") or a.get("description"),
                    "details": a.get("details") or {},
                    "risk_score": a.get("risk_score", 0),
                    "is_resolved": a.get("is_resolved", False),
                }
                for a in alerts
            ]

    if simulation_fallback_enabled() and STATE_FILE.exists():
        try:
            with open(STATE_FILE, "r", encoding="utf-8") as f:
                state = json.load(f)
                return state.get("events", [])
        except Exception:
            pass
    return []

@router.get("/inventory/units")
async def get_units(
    request: Request,
    tenant_id: Optional[str] = None,
    tenant: TenantContext = Depends(require_tenant_context)
):
    effective_tenant = tenant.tenant_id if _is_real_tenant_id(tenant.tenant_id) else tenant_id
    if _is_real_tenant_id(effective_tenant):
        db_units = await _fetch_db_units(request, effective_tenant)
        if db_units is not None:
            return db_units

    if simulation_fallback_enabled() and STATE_FILE.exists():
        try:
            with open(STATE_FILE, "r", encoding="utf-8") as f:
                state = json.load(f)
                return state.get("units", [])
        except Exception:
            pass
    return []

def _machine_sequence(machine: Dict[str, Any]) -> int:
    try:
        return int(str(machine.get("id", "")).split("-")[-1])
    except Exception:
        return 1

def _enrich_machine_for_inventory(machine: Dict[str, Any]) -> Dict[str, Any]:
    item = dict(machine)
    unit = str(item.get("unit") or "UN-00")
    seq = _machine_sequence(item)
    telemetry = item.get("telemetry") or {}
    disk_used_pct = int(telemetry.get("disk") or 50)
    disk_total = 512 if seq % 3 else 256
    disk_free = max(12, round(disk_total * (100 - disk_used_pct) / 100))

    inventory = dict(item.get("inventory_data") or {})
    system_details = dict(inventory.get("system_details") or {})
    system_details.setdefault("active_user", f"{unit.lower()}\\operador{seq:03d}")
    system_details.setdefault("local_ip", item.get("ip") or "0.0.0.0")
    system_details.setdefault("disk_total_gb", disk_total)
    system_details.setdefault("disk_free_gb", disk_free)
    system_details.setdefault("domain", f"VEXT-{unit}")
    inventory["system_details"] = system_details

    if not item.get("serial_number"):
        item["serial_number"] = f"VEXT-{unit.replace('-', '')}-{seq:05d}"

    item["inventory_data"] = inventory
    return item

@router.get("/inventory/machines")
async def get_machines(
    request: Request,
    unit_id: Optional[str] = None,
    tenant_id: Optional[str] = None,
    tenant: TenantContext = Depends(require_tenant_context)
):
    effective_tenant = tenant.tenant_id if _is_real_tenant_id(tenant.tenant_id) else tenant_id
    if _is_real_tenant_id(effective_tenant):
        db_machines = await _fetch_db_machines(request, unit_id, effective_tenant)
        if db_machines is not None:
            return [_enrich_machine_for_inventory(m) for m in db_machines]

    if simulation_fallback_enabled() and STATE_FILE.exists():
        try:
            with open(STATE_FILE, "r", encoding="utf-8") as f:
                state = json.load(f)
                machines = state.get("machines", [])
                if unit_id:
                    machines = [m for m in machines if m.get("unit") == unit_id]
                return [_enrich_machine_for_inventory(m) for m in machines[:500]]
        except Exception:
            pass
    return []

@router.get("/compliance/alerts")
async def get_compliance_alerts(
    request: Request,
    tenant_id: Optional[str] = None,
    limit: int = 500,
    tenant: TenantContext = Depends(require_tenant_context)
):
    effective_tenant = tenant.tenant_id if _is_real_tenant_id(tenant.tenant_id) else tenant_id
    if _is_real_tenant_id(effective_tenant):
        db_alerts = await _fetch_db_alerts(request, effective_tenant, limit=limit)
        if db_alerts is not None:
            return db_alerts

    if simulation_fallback_enabled() and STATE_FILE.exists():
        try:
            with open(STATE_FILE, "r", encoding="utf-8") as f:
                state = json.load(f)
            if "compliance_alerts" in state and isinstance(state["compliance_alerts"], list):
                return state["compliance_alerts"][:limit]
            events = state.get("events", [])
            alerts = []
            for ev in events[:limit]:
                alerts.append({
                    "id": ev.get("id"),
                    "machine_id": ev.get("machine"),
                    "hostname": ev.get("agent_hostname") or ev.get("machine"),
                    "unit": ev.get("unit"),
                    "software_name": ev.get("details", {}).get("software_name") if isinstance(ev.get("details"), dict) else None,
                    "message": ev.get("description") or ev.get("type"),
                    "severity": str(ev.get("severity") or "medium").lower(),
                    "risk_score": ev.get("risk_score") or 50,
                    "detection_category": ev.get("type") or "compliance",
                    "details": ev.get("details") or {},
                    "created_at": ev.get("timestamp"),
                    "is_resolved": False,
                })
            return alerts
        except Exception as exc:
            logger.warning(f"Error loading simulation compliance alerts: {exc}")
    return []

@router.get("/agent/commands")
async def get_agent_commands(
    request: Request,
    machine_id: Optional[str] = None,
    tenant_id: Optional[str] = None,
    limit: int = 100,
    tenant: TenantContext = Depends(require_tenant_context)
):
    effective_tenant = tenant.tenant_id if _is_real_tenant_id(tenant.tenant_id) else tenant_id
    if _is_real_tenant_id(effective_tenant):
        db_commands = await _fetch_db_commands(request, effective_tenant, machine_id=machine_id, limit=limit)
        if db_commands is not None:
            return db_commands

    if simulation_fallback_enabled() and STATE_FILE.exists():
        try:
            with open(STATE_FILE, "r", encoding="utf-8") as f:
                state = json.load(f)
            commands = state.get("agent_commands", [])
            if machine_id:
                commands = [c for c in commands if c.get("machine_id") == machine_id]
            return commands[:limit]
        except Exception as exc:
            logger.warning(f"Error loading simulation agent commands: {exc}")
    return []
