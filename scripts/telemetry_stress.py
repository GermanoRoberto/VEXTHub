# -*- coding: utf-8 -*-
"""High-volume local telemetry stress runner for VextHub.

Default mode is intentionally safe for local development: it sends authenticated
telemetry to /api/telemetry with x-vexthub-simulation=stress and skips Redis so
the app mirrors pulses into simulation_state.json immediately. Use --queue to
exercise the Redis/worker path.
"""

from __future__ import annotations

import argparse
import copy
import json
import math
import os
import random
import statistics
import sys
import time
import urllib.error
import urllib.request
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from typing import Any

if sys.platform == "win32":
    import io

    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")

ROOT = Path(__file__).resolve().parent.parent
STATE_FILE = ROOT / "scripts" / "simulation_state.json"
SCRATCH_DIR = ROOT / "scratch"

SUSPICIOUS_SOFTWARE = [
    {"name": "RustDesk", "publisher": "RustDesk", "version": "1.2.3"},
    {"name": "TeamViewer", "publisher": "TeamViewer Germany GmbH", "version": "15.50.5"},
    {"name": "Advanced IP Scanner", "publisher": "Famatech Corp.", "version": "2.5.4594"},
    {"name": "Process Hacker", "publisher": "wj32", "version": "2.39.124"},
    {"name": "Mimikatz", "publisher": "gentilkiwi", "version": "2.2.0-20220919"},
]

VULNERABLE_SOFTWARE = [
    {"name": "Log4j Vulnerable App", "publisher": "Apache", "version": "2.14.1", "cve": "CVE-2021-44228", "severity": "CRITICAL"},
    {"name": "Old Google Chrome", "publisher": "Google LLC", "version": "90.0.4430.212", "cve": "CVE-2021-30551", "severity": "CRITICAL"},
    {"name": "OpenSSL Old", "publisher": "OpenSSL", "version": "1.0.1", "cve": "CVE-2014-0160", "severity": "HIGH"},
    {"name": "WinRAR Exploit", "publisher": "win.rar GmbH", "version": "6.22", "cve": "CVE-2023-38831", "severity": "HIGH"},
]

BACKGROUND_SOFTWARE = [
    {"name": "Microsoft Defender", "publisher": "Microsoft Corporation", "version": "4.18"},
    {"name": "Google Chrome", "publisher": "Google LLC", "version": "121.0.6167.85"},
    {"name": "Microsoft Office Professional Plus 2021", "publisher": "Microsoft Corporation", "version": "16.0"},
    {"name": "SAP GUI for Windows", "publisher": "SAP SE", "version": "770"},
    {"name": "Zoom", "publisher": "Zoom Video Communications, Inc.", "version": "5.17.5"},
]

SCENARIOS = {
    "baseline": {"risk": 0.03, "vuln": 0.02, "payload_bloat": 0, "cpu_bias": 0},
    "incident-storm": {"risk": 0.22, "vuln": 0.10, "payload_bloat": 8, "cpu_bias": 35},
    "patch-tuesday": {"risk": 0.06, "vuln": 0.04, "payload_bloat": 35, "cpu_bias": 18},
    "brownout": {"risk": 0.08, "vuln": 0.03, "payload_bloat": 4, "cpu_bias": 55},
    "chaos": {"risk": 0.15, "vuln": 0.08, "payload_bloat": 18, "cpu_bias": 25},
}


def now_iso() -> str:
    return datetime.now().isoformat()


def load_env_file(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    if not path.exists():
        return values

    for raw in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key.strip()] = value.strip().strip('"').strip("'")
    return values


def load_secret(explicit: str | None) -> str:
    if explicit:
        return explicit
    env = load_env_file(ROOT / ".env")
    secret = os.getenv("AGENT_SHARED_SECRET") or env.get("AGENT_SHARED_SECRET")
    if not secret:
        raise SystemExit("AGENT_SHARED_SECRET nao encontrado no ambiente nem em .env.")
    return secret


def load_state() -> dict[str, Any]:
    if not STATE_FILE.exists():
        raise SystemExit(f"Estado de simulacao nao encontrado: {STATE_FILE}. Rode scripts/telemetry_simulator.py --reset.")
    return json.loads(STATE_FILE.read_text(encoding="utf-8"))


def write_state(state: dict[str, Any]) -> None:
    tmp = STATE_FILE.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(state, indent=2, ensure_ascii=False), encoding="utf-8")
    tmp.replace(STATE_FILE)


def percentiles(values: list[float]) -> dict[str, float]:
    if not values:
        return {"avg_ms": 0, "p50_ms": 0, "p95_ms": 0, "p99_ms": 0, "max_ms": 0}
    ordered = sorted(values)

    def pick(p: float) -> float:
        idx = min(len(ordered) - 1, max(0, math.ceil((p / 100) * len(ordered)) - 1))
        return round(ordered[idx], 2)

    return {
        "avg_ms": round(statistics.fmean(ordered), 2),
        "p50_ms": pick(50),
        "p95_ms": pick(95),
        "p99_ms": pick(99),
        "max_ms": round(max(ordered), 2),
    }


def clamp(value: int, low: int = 1, high: int = 100) -> int:
    return max(low, min(high, int(value)))


def base_software(machine: dict[str, Any]) -> list[dict[str, Any]]:
    inventory = machine.get("inventory_data") or {}
    software = inventory.get("software")
    if isinstance(software, list) and software:
        return copy.deepcopy(software[:12])
    return copy.deepcopy(BACKGROUND_SOFTWARE)


def build_network_connections(rng: random.Random, risky: bool) -> dict[str, Any]:
    listening = [
        {"protocol": "tcp", "local_address": "127.0.0.1", "local_port": 445, "exposure": "loopback"},
    ]
    external = []

    if risky:
        listening.append({"protocol": "tcp", "local_address": "0.0.0.0", "local_port": rng.choice([3389, 5900, 5985]), "exposure": "all_interfaces"})
        external.append({
            "protocol": "tcp",
            "local_address": f"10.{rng.randint(1, 27)}.{rng.randint(0, 4)}.{rng.randint(10, 250)}",
            "local_port": rng.randint(20000, 65000),
            "remote_address": rng.choice(["198.51.100.42", "203.0.113.77", "45.133.216.9", "185.220.101.44"]),
            "remote_port": rng.choice([443, 4444, 8080, 9001]),
            "state": "Established",
        })

    return {"listening_tcp_ports": listening, "established_external_tcp": external}


def build_processes(rng: random.Random, risky: bool, cpu_bias: int) -> list[dict[str, Any]]:
    processes = [
        {"name": "VextHubAgent.exe", "cpu": round(rng.uniform(0.1, 2.2), 2)},
        {"name": "MsMpEng.exe", "cpu": round(rng.uniform(0.5, 5.5), 2)},
        {"name": "chrome.exe", "cpu": round(rng.uniform(0.5, 12.0), 2)},
    ]
    if risky:
        processes.extend([
            {"name": "powershell.exe", "cpu": round(rng.uniform(5, 28) + cpu_bias / 8, 2), "command_line": "powershell.exe -NoProfile -EncodedCommand <redacted>"},
            {"name": rng.choice(["rustdesk.exe", "teamviewer.exe", "procexp64.exe"]), "cpu": round(rng.uniform(0.4, 8.0), 2)},
        ])
    return processes


def build_payload(machine: dict[str, Any], scenario: str, sequence: int, tenant_id: str, rng: random.Random) -> dict[str, Any]:
    profile = SCENARIOS[scenario]
    risky = rng.random() < profile["risk"]
    vulnerable = rng.random() < profile["vuln"]
    telemetry = machine.get("telemetry") or {}
    cpu = clamp(int(telemetry.get("cpu", 20)) + rng.randint(-8, 12) + (profile["cpu_bias"] if risky else 0), 1, 100)
    ram = clamp(int(telemetry.get("ram", 45)) + rng.randint(-5, 10) + (12 if scenario in {"brownout", "patch-tuesday"} else 0), 5, 100)
    disk = clamp(int(telemetry.get("disk", 50)) + rng.randint(-2, 4), 1, 99)

    software = base_software(machine)
    vulnerabilities = []
    if risky:
        software.append(copy.deepcopy(rng.choice(SUSPICIOUS_SOFTWARE)))
    if vulnerable:
        item = copy.deepcopy(rng.choice(VULNERABLE_SOFTWARE))
        software.append({k: item[k] for k in ("name", "publisher", "version")})
        vulnerabilities.append({"cve": item["cve"], "severity": item["severity"], "software": item["name"]})

    for idx in range(profile["payload_bloat"]):
        software.append({
            "name": f"Synthetic Package {idx:03d}",
            "publisher": "VextHub Stress Lab",
            "version": f"{rng.randint(1, 9)}.{rng.randint(0, 99)}.{rng.randint(0, 999)}",
            "install_date": "2026-05-15",
            "hash_sha256": uuid.uuid4().hex,
        })

    machine_id = machine["id"]
    hostname = machine.get("hostname") or machine_id
    unit = machine.get("unit") or "UN-STRESS"
    ip = machine.get("ip") or f"10.250.{sequence % 20}.{sequence % 240 + 10}"
    serial = machine.get("serial_number") or f"VEXT-{unit.replace('-', '')}-{sequence:05d}"
    disk_total = 256 if sequence % 3 == 0 else 512
    disk_free = max(8, round(disk_total * (100 - disk) / 100))

    return {
        "tenant_id": tenant_id,
        "machine_id": machine_id,
        "hostname": hostname,
        "unit": unit,
        "ip": ip,
        "serial_number": serial,
        "os_name": machine.get("os_name") or rng.choice(["Windows 11 Pro", "Windows 10 Business", "Windows Server 2022"]),
        "cpu_info": machine.get("cpu_info") or rng.choice(["Intel Core i7", "AMD Ryzen 5", "Intel Xeon"]),
        "ram_total": machine.get("ram_total") or rng.choice(["8GB", "16GB", "32GB"]),
        "agent_version": rng.choice(["3.4.4", "4.0.0", "4.1.0"]),
        "telemetry": {"cpu": cpu, "ram": ram, "disk": disk},
        "inventory_data": {
            "software": software,
            "vulnerabilities": vulnerabilities,
            "is_infected": risky,
            "processes": build_processes(rng, risky, profile["cpu_bias"]),
            "services": [{"name": "VextHubAgent", "state": "Running", "start_mode": "Auto"}],
            "startup_entries": [{"name": "VextHubAgent", "path": "C:\\Program Files\\VextHub\\VextHubAgent.exe"}],
            "network_connections": build_network_connections(rng, risky),
            "network_assets": machine.get("inventory_data", {}).get("network_assets", []),
            "system_details": {
                "active_user": f"{unit.lower()}\\operador{sequence % 997:03d}",
                "local_ip": ip,
                "disk_total_gb": disk_total,
                "disk_free_gb": disk_free,
                "domain": f"VEXT-{unit}",
            },
            "stress_context": {
                "scenario": scenario,
                "sequence": sequence,
                "risky": risky,
                "generated_at": now_iso(),
            },
        },
    }


def post_json(url: str, payload: dict[str, Any], headers: dict[str, str], timeout: float) -> dict[str, Any]:
    raw = json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(url, data=raw, method="POST", headers={
        "Content-Type": "application/json",
        **headers,
    })
    started = time.perf_counter()
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            body = response.read().decode("utf-8", errors="replace")
            elapsed = (time.perf_counter() - started) * 1000
            parsed = json.loads(body) if body else {}
            return {
                "ok": 200 <= response.status < 300,
                "status": response.status,
                "latency_ms": elapsed,
                "commands": len(parsed.get("commands") or []),
                "response_status": parsed.get("status"),
                "error": None,
            }
    except urllib.error.HTTPError as exc:
        elapsed = (time.perf_counter() - started) * 1000
        body = exc.read().decode("utf-8", errors="replace")
        return {"ok": False, "status": exc.code, "latency_ms": elapsed, "commands": 0, "response_status": None, "error": body[:300]}
    except Exception as exc:
        elapsed = (time.perf_counter() - started) * 1000
        return {"ok": False, "status": "EXC", "latency_ms": elapsed, "commands": 0, "response_status": None, "error": str(exc)[:300]}


def summarize(results: list[dict[str, Any]], started_at: float, total_planned: int) -> dict[str, Any]:
    elapsed = max(0.001, time.perf_counter() - started_at)
    latencies = [float(r["latency_ms"]) for r in results if isinstance(r.get("latency_ms"), (int, float))]
    statuses: dict[str, int] = {}
    response_statuses: dict[str, int] = {}
    for result in results:
        statuses[str(result["status"])] = statuses.get(str(result["status"]), 0) + 1
        if result.get("response_status"):
            response_statuses[str(result["response_status"])] = response_statuses.get(str(result["response_status"]), 0) + 1

    ok = sum(1 for r in results if r.get("ok"))
    return {
        "planned": total_planned,
        "completed": len(results),
        "ok": ok,
        "failed": len(results) - ok,
        "success_rate": round((ok / len(results)) * 100, 2) if results else 0,
        "throughput_rps": round(len(results) / elapsed, 2),
        "commands_delivered": sum(int(r.get("commands") or 0) for r in results),
        "http_statuses": statuses,
        "response_statuses": response_statuses,
        **percentiles(latencies),
    }


def update_stress_metrics(report: dict[str, Any]) -> None:
    try:
        state = load_state()
        metrics = state.get("stress_metrics") or {}
        metrics.update({
            "last_stress_report": report,
            "last_stress_at": now_iso(),
            "scenario": report["scenario"],
            "planned_pulses": report["summary"]["planned"],
            "completed_pulses": report["summary"]["completed"],
            "ok_pulses": report["summary"]["ok"],
            "failed_pulses": report["summary"]["failed"],
            "throughput_rps": report["summary"]["throughput_rps"],
            "p95_ms": report["summary"]["p95_ms"],
        })
        state["stress_metrics"] = metrics
        write_state(state)
    except Exception:
        pass


def main() -> None:
    parser = argparse.ArgumentParser(description="Stress /api/telemetry with synthetic endpoint pulses.")
    parser.add_argument("--base-url", default="http://localhost:3000")
    parser.add_argument("--tenant-id", default="00000000-0000-0000-0000-000000000000")
    parser.add_argument("--secret", default=None, help="Agent shared secret. Defaults to AGENT_SHARED_SECRET/.env.")
    parser.add_argument("--scenario", choices=sorted(SCENARIOS), default="chaos")
    parser.add_argument("--duration", type=int, default=30)
    parser.add_argument("--rps", type=float, default=25)
    parser.add_argument("--concurrency", type=int, default=64)
    parser.add_argument("--machines", type=int, default=500)
    parser.add_argument("--timeout", type=float, default=5.0)
    parser.add_argument("--seed", type=int, default=None)
    parser.add_argument("--queue", action="store_true", help="Exercise Redis/worker queue instead of local mirror only.")
    parser.add_argument("--report", default=None)
    args = parser.parse_args()

    secret = load_secret(args.secret)
    state = load_state()
    machines = state.get("machines") or []
    if not machines:
        raise SystemExit("simulation_state.json nao contem machines.")

    rng = random.Random(args.seed or int(time.time()))
    selected = rng.sample(machines, min(len(machines), max(1, args.machines)))
    total = max(1, int(args.duration * args.rps))
    url = args.base_url.rstrip("/") + "/api/telemetry"
    headers = {
        "x-agent-key": secret,
        "x-vexthub-simulation": "stress",
    }
    if not args.queue:
        headers["x-vexthub-skip-queue"] = "true"

    print(
        f"Stress start: scenario={args.scenario} pulses={total} "
        f"rps={args.rps} concurrency={args.concurrency} machines={len(selected)} queue={args.queue}"
    )

    started = time.perf_counter()
    results: list[dict[str, Any]] = []
    futures = []

    with ThreadPoolExecutor(max_workers=args.concurrency) as executor:
        for sequence in range(total):
            machine = selected[sequence % len(selected)]
            payload = build_payload(machine, args.scenario, sequence, args.tenant_id, rng)
            futures.append(executor.submit(post_json, url, payload, headers, args.timeout))

            target_time = started + ((sequence + 1) / args.rps)
            delay = target_time - time.perf_counter()
            if delay > 0:
                time.sleep(min(delay, 0.25))

        last_print = time.perf_counter()
        for future in as_completed(futures):
            results.append(future.result())
            if time.perf_counter() - last_print >= 1:
                current = summarize(results, started, total)
                print(
                    f"  {current['completed']}/{total} ok={current['ok']} fail={current['failed']} "
                    f"rps={current['throughput_rps']} p95={current['p95_ms']}ms"
                )
                last_print = time.perf_counter()

    report = {
        "generated_at": now_iso(),
        "scenario": args.scenario,
        "base_url": args.base_url,
        "queue_enabled": args.queue,
        "duration_seconds": args.duration,
        "target_rps": args.rps,
        "concurrency": args.concurrency,
        "machine_pool": len(selected),
        "summary": summarize(results, started, total),
        "sample_errors": [r for r in results if not r.get("ok")][:10],
    }

    SCRATCH_DIR.mkdir(exist_ok=True)
    report_path = Path(args.report) if args.report else SCRATCH_DIR / f"telemetry-stress-{datetime.now().strftime('%Y%m%d-%H%M%S')}.json"
    report_path.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    update_stress_metrics(report)

    print(json.dumps(report["summary"], indent=2, ensure_ascii=False))
    print(f"Stress report: {report_path}")


if __name__ == "__main__":
    main()
