# -*- coding: utf-8 -*-
"""Build and tick the local VextHub simulation state.

This file is intentionally local/dev only. Production ingestion must use
Supabase/Postgres through the application APIs.
"""

from __future__ import annotations

import argparse
import json
import os
import random
import sys
import time
import uuid
from datetime import datetime, timedelta
from pathlib import Path

if sys.platform == "win32":
    import io

    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", write_through=True)

STATE_FILE = Path(__file__).resolve().parent / "simulation_state.json"

BRAZIL_CITIES = [
    ("Sao Paulo", "SP", -23.5505, -46.6333),
    ("Rio de Janeiro", "RJ", -22.9068, -43.1729),
    ("Brasilia", "DF", -15.7801, -47.9292),
    ("Salvador", "BA", -12.9714, -38.5014),
    ("Fortaleza", "CE", -3.7172, -38.5433),
    ("Belo Horizonte", "MG", -19.9167, -43.9345),
    ("Manaus", "AM", -3.1190, -60.0217),
    ("Curitiba", "PR", -25.4290, -49.2671),
    ("Recife", "PE", -8.0476, -34.8770),
    ("Goiania", "GO", -16.6869, -49.2648),
    ("Belem", "PA", -1.4558, -48.4902),
    ("Porto Alegre", "RS", -30.0346, -51.2177),
    ("Guarulhos", "SP", -23.4542, -46.5333),
    ("Campinas", "SP", -22.9099, -47.0626),
    ("Sao Luis", "MA", -2.5307, -44.3068),
    ("Maceio", "AL", -9.6658, -35.7353),
    ("Natal", "RN", -5.7945, -35.2110),
    ("Teresina", "PI", -5.0919, -42.8034),
    ("Campo Grande", "MS", -20.4697, -54.6201),
    ("Osasco", "SP", -23.5325, -46.7917),
    ("Joao Pessoa", "PB", -7.1195, -34.8450),
    ("Contagem", "MG", -19.9322, -44.0539),
    ("Uberlandia", "MG", -18.9186, -48.2772),
    ("Sorocaba", "SP", -23.5017, -47.4581),
    ("Ribeirao Preto", "SP", -21.1775, -47.8103),
    ("Cuiaba", "MT", -15.6010, -56.0974),
    ("Joinville", "SC", -26.3044, -48.8456),
]

GOOD_SOFTWARE = [
    ("Google Chrome", "Google LLC", "121.0.6167.85"),
    ("Microsoft Office Professional Plus 2021", "Microsoft Corporation", "16.0.14332.20204"),
    ("Zoom", "Zoom Video Communications, Inc.", "5.17.5"),
    ("Slack", "Slack Technologies", "4.36.0"),
    ("Visual Studio Code", "Microsoft Corporation", "1.86.0"),
    ("WinRAR", "win.rar GmbH", "6.24.0"),
    ("SAP GUI for Windows", "SAP SE", "770"),
    ("Adobe Acrobat Reader", "Adobe", "23.008.20470"),
    ("Spotify", "Spotify AB", "1.2.26.1187"),
]

VULNERABLE_SOFTWARE = [
    ("Old Google Chrome", "Google LLC", "90.0.4430.212", "CVE-2021-30551", "CRITICAL"),
    ("Log4j Vulnerable App", "Apache", "2.14.1", "CVE-2021-44228", "CRITICAL"),
    ("OpenSSL Old", "OpenSSL", "1.0.1", "CVE-2014-0160", "HIGH"),
    ("WinRAR Exploit", "win.rar GmbH", "6.22", "CVE-2023-38831", "HIGH"),
]

GAMES = [
    ("Valorant", "Riot Games", "8.02.0.2225367"),
    ("Counter-Strike 2", "Valve", "1.39.8.5"),
    ("League of Legends", "Riot Games", "14.3.559.1834"),
    ("Roblox", "Roblox Corporation", "0.611.0.12345"),
    ("Steam", "Valve Corporation", "2.10.91.91"),
]

SUSPICIOUS_SOFTWARE = [
    ("AnyDesk", "AnyDesk Software GmbH", "7.1.13"),
    ("TeamViewer", "TeamViewer Germany GmbH", "15.50.5"),
    ("RustDesk", "RustDesk", "1.2.3"),
    ("Advanced IP Scanner", "Famatech Corp.", "2.5.4594"),
    ("Mimikatz", "gentilkiwi", "2.2.0-20220919"),
    ("Process Hacker", "wj32", "2.39.124"),
    ("Wireshark", "The Wireshark developer community", "4.2.2"),
]


def iso_now() -> str:
    return datetime.now().isoformat()


def machine_sequence(machine_id: str) -> int:
    try:
        return int(str(machine_id).split("-")[-1])
    except Exception:
        return 1


def build_serial_number(unit_id: str, machine_id: str) -> str:
    return f"VEXT-{unit_id.replace('-', '')}-{machine_sequence(machine_id):05d}"


def build_system_details(unit_id: str, machine_id: str, ip: str, disk_used_pct: int) -> dict:
    seq = machine_sequence(machine_id)
    disk_total = 512 if seq % 3 else 256
    disk_free = max(12, round(disk_total * (100 - int(disk_used_pct)) / 100))
    return {
        "active_user": f"{unit_id.lower()}\\operador{seq:03d}",
        "local_ip": ip,
        "disk_total_gb": disk_total,
        "disk_free_gb": disk_free,
        "domain": f"VEXT-{unit_id}",
    }


def software_item(entry: tuple[str, str, str]) -> dict:
    return {
        "name": entry[0],
        "publisher": entry[1],
        "version": entry[2],
        "install_date": (datetime.now() - timedelta(days=random.randint(1, 365))).strftime("%Y-%m-%d"),
        "hash_sha256": uuid.uuid4().hex,
    }


def generate_software_list() -> tuple[list[dict], bool, list[dict]]:
    selected = [GOOD_SOFTWARE[0], GOOD_SOFTWARE[1]]
    selected.extend(random.sample(GOOD_SOFTWARE[2:], random.randint(3, 5)))

    if random.random() < 0.30:
        selected.extend(random.sample(GAMES, random.randint(1, 3)))

    vulnerabilities = []
    if random.random() < 0.10:
        vulnerable = random.choice(VULNERABLE_SOFTWARE)
        selected.append(vulnerable[:3])
        vulnerabilities.append({"cve": vulnerable[3], "severity": vulnerable[4], "software": vulnerable[0]})

    is_infected = random.random() < 0.15
    if is_infected:
        selected.extend(random.sample(SUSPICIOUS_SOFTWARE, random.randint(1, 2)))

    return [software_item(item) for item in selected], is_infected, vulnerabilities


def generate_network_assets(unit_id: str) -> list[dict]:
    assets = []
    asset_types = ["Printer", "Server", "VoIP Phone", "IP Camera", "Switch", "NAS"]
    vendors = ["HP", "Dell", "Cisco", "Hikvision", "Ubiquiti", "Synology"]

    for idx in range(random.randint(8, 20)):
        asset_type = random.choice(asset_types)
        assets.append({
            "id": f"{unit_id}-AST-{idx + 1:03d}",
            "hostname": f"VEXT-{unit_id}-{asset_type.upper().replace(' ', '-')}-{idx + 1:03d}",
            "ip": f"10.200.{random.randint(0, 255)}.{random.randint(2, 254)}",
            "mac": f"00:1A:2B:3C:{random.randint(16, 255):02X}:{random.randint(16, 255):02X}",
            "device_type": asset_type,
            "vendor": random.choice(vendors),
            "status": "online" if random.random() > 0.08 else "offline",
        })
    return assets


def build_machine(unit_index: int, unit_id: str, machine_index: int) -> dict:
    machine_id = f"{unit_id}-PC-{machine_index + 1:03d}"
    ip = f"10.{unit_index + 1}.{machine_index // 25}.{machine_index % 25 + 10}"
    disk_used = random.randint(15, 90)
    software, is_infected, vulnerabilities = generate_software_list()
    os_name = "Windows 11 Pro" if random.random() > 0.3 else "Windows 10 Business"

    return {
        "id": machine_id,
        "hostname": f"VEXT-{unit_id}-{machine_index + 1:03d}",
        "ip": ip,
        "unit": unit_id,
        "status": "online" if random.random() > 0.1 else "offline",
        "last_pulse": iso_now(),
        "os_name": os_name,
        "cpu_info": random.choice(["Intel(R) Core(TM) i7-12700K", "AMD Ryzen 5 5600X", "Intel Core i5-10500"]),
        "ram_total": random.choice(["8GB", "16GB", "32GB"]),
        "serial_number": build_serial_number(unit_id, machine_id),
        "agent_version": random.choice(["3.4.4", "4.0.0", "4.1.0"]),
        "inventory_data": {
            "software": software,
            "vulnerabilities": vulnerabilities,
            "is_infected": is_infected,
            "system_details": build_system_details(unit_id, machine_id, ip, disk_used),
            "processes": [
                {"name": "chrome.exe", "cpu": 1.2},
                {"name": "svchost.exe", "cpu": 0.1},
                {"name": "VextHubAgent.exe", "cpu": 0.3},
            ],
            "services": [],
            "startup_entries": [],
        },
        "telemetry": {
            "cpu": random.randint(5, 45),
            "ram": random.randint(20, 75),
            "disk": disk_used,
        },
    }


def generate_initial_state(units_count: int = 27, machines_per_unit: int = 100) -> dict:
    selected_cities = BRAZIL_CITIES[:]
    random.shuffle(selected_cities)
    selected_cities = selected_cities[: min(len(selected_cities), units_count)]
    units = []
    machines = []

    for unit_index, (city, state, lat, lon) in enumerate(selected_cities):
        unit_id = f"UN-{unit_index + 1:02d}"
        units.append({
            "id": unit_id,
            "name": f"VEXT {city}",
            "city": city,
            "state": state,
            "location": f"{city}, {state}",
            "lat": lat,
            "lon": lon,
            "agent_key": f"v_key_sim_{unit_index + 1:03d}_{random.getrandbits(32):x}",
            "x": random.randint(10, 90),
            "y": random.randint(10, 90),
            "network_assets": generate_network_assets(unit_id),
        })

        for machine_index in range(machines_per_unit):
            machines.append(build_machine(unit_index, unit_id, machine_index))

    return {
        "units": units,
        "machines": machines,
        "events": [],
        "agent_commands": [],
        "stress_metrics": {
            "generated_at": iso_now(),
            "total_pulses": 0,
            "scenario": "seed",
        },
    }


def load_state() -> dict:
    if not STATE_FILE.exists():
        return generate_initial_state()

    for attempt in range(3):
        try:
            content = STATE_FILE.read_text(encoding="utf-8")
            if content and content.strip():
                return json.loads(content)
        except Exception:
            time.sleep(0.05)

    return generate_initial_state()


def tick_machine(machine: dict, state: dict) -> None:
    machine_id = machine.get("id", "UN-00-PC-001")
    unit_id = machine.get("unit", "UN-00")
    ip = machine.get("ip", "0.0.0.0")
    telemetry = machine.setdefault("telemetry", {"cpu": 10, "ram": 30, "disk": 50})
    inventory = machine.setdefault("inventory_data", {})
    inventory.setdefault("software", [])
    inventory.setdefault("processes", [])

    machine.setdefault("serial_number", build_serial_number(unit_id, machine_id))
    system_details = inventory.setdefault("system_details", {})
    for key, value in build_system_details(unit_id, machine_id, ip, telemetry.get("disk", 50)).items():
        system_details.setdefault(key, value)

    if machine.get("status") == "offline" and random.random() < 0.04:
        machine["status"] = "online"
    elif machine.get("status") == "online" and random.random() < 0.01:
        machine["status"] = "offline"

    if machine.get("status") != "online":
        return

    telemetry["cpu"] = max(2, min(100, int(telemetry.get("cpu", 10)) + random.randint(-10, 12)))
    telemetry["ram"] = max(10, min(98, int(telemetry.get("ram", 30)) + random.randint(-5, 6)))
    telemetry["disk"] = max(5, min(99, int(telemetry.get("disk", 50)) + random.randint(-2, 3)))
    machine["last_pulse"] = iso_now()

    # Dynamic Simulation: Gradual Agent Rollout
    LATEST_VERSION = "4.2.0-stable"
    if machine.get("agent_version") != LATEST_VERSION:
        # 1% chance per tick to upgrade the agent
        if random.random() < 0.01:
            machine["agent_version"] = LATEST_VERSION

    # Dynamic Simulation: Randomly change software inventory over time
    if random.random() < 0.02:
        new_software, new_infected, new_vulns = generate_software_list()
        inventory["software"] = new_software
        inventory["is_infected"] = new_infected
        inventory["vulnerabilities"] = new_vulns

    vulnerabilities = inventory.get("vulnerabilities") or []
    if inventory.get("is_infected") and random.random() < 0.02:
        state["events"].insert(0, {
            "id": str(uuid.uuid4()),
            "timestamp": iso_now(),
            "agent_hostname": machine.get("hostname"),
            "unit": unit_id,
            "severity": "HIGH",
            "type": random.choice([
                "Cortex Forensics: Ferramenta de acesso remoto detectada",
                "Cortex Neural: Processo com comportamento suspeito",
                "Cortex Guardian: Persistencia em inicializacao detectada",
            ]),
        })

    if vulnerabilities and random.random() < 0.01:
        state["events"].insert(0, {
            "id": str(uuid.uuid4()),
            "timestamp": iso_now(),
            "agent_hostname": machine.get("hostname"),
            "unit": unit_id,
            "severity": "CRITICAL",
            "type": f"Exploit Detectado: {vulnerabilities[0]['cve']}",
        })


def update_simulation(state: dict | None = None) -> dict:
    if state is None:
        state = load_state()
    state.setdefault("events", [])
    state.setdefault("agent_commands", [])
    
    # Track ticks
    stress = state.setdefault("stress_metrics", {})
    total_ticks = stress.get("total_ticks", 0) + 1
    stress["total_ticks"] = total_ticks

    # INJECT CUSTOM MACHINE AT 600 TICKS (approx 2 minutes)
    if total_ticks == 600:
        custom_machine = {
            "id": "UN-99-PC-001",
            "hostname": "PE0D7QQS",
            "ip": "10.0.0.155",
            "unit": "UN-99",
            "status": "online",
            "last_pulse": iso_now(),
            "os_name": "Microsoft Windows 11 Pro",
            "cpu_info": "AMD Ryzen 7 7730U with Radeon Graphics",
            "ram_total": "16GB",
            "serial_number": "VEXT-UN99-00001",
            "agent_version": "4.2.0-stable",
            "inventory_data": {
                "software": [
                    {"name": "Google Chrome", "publisher": "Google LLC", "version": "121", "install_date": "2026-05-01", "hash_sha256": "abcdef123"},
                    {"name": "Bitdefender Endpoint Security Tools", "publisher": "Bitdefender", "version": "7.9", "install_date": "2026-05-18", "hash_sha256": "def456"},
                    {"name": "AnyDesk", "publisher": "AnyDesk Software GmbH", "version": "7.1", "install_date": "2026-05-18", "hash_sha256": "sus123"}
                ],
                "vulnerabilities": [],
                "is_infected": True,
                "system_details": {
                    "active_user": "un-99\\operador001",
                    "local_ip": "10.0.0.155",
                    "disk_total_gb": 512,
                    "disk_free_gb": 120,
                    "domain": "VEXT-UN-99"
                },
                "processes": [],
                "services": [],
                "startup_entries": [],
            },
            "telemetry": {"cpu": 15, "ram": 45, "disk": 75},
        }
        state["machines"].append(custom_machine)
        state["events"].insert(0, {
            "id": str(uuid.uuid4()),
            "timestamp": iso_now(),
            "agent_hostname": "PE0D7QQS",
            "unit": "UN-99",
            "severity": "CRITICAL",
            "type": "Cortex Forensics: Novo endpoint registrado com software de risco (AnyDesk)",
        })
        print("\n[+] MÁQUINA FÍSICA DO USUÁRIO (PE0D7QQS) INJETADA NO SIMULADOR!\n", flush=True)

    for machine in state.get("machines", []):
        tick_machine(machine, state)

    state["events"] = state["events"][:1000]
    try:
        tmp_file = STATE_FILE.with_suffix(".json.tmp")
        tmp_file.write_text(json.dumps(state, indent=2, ensure_ascii=False), encoding="utf-8")
        tmp_file.replace(STATE_FILE)
    except Exception:
        pass
    return state


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate or tick VextHub local simulation state.")
    parser.add_argument("--reset", action="store_true", help="Regenerate the whole local state.")
    parser.add_argument("--units", type=int, default=27)
    parser.add_argument("--machines-per-unit", type=int, default=100)
    parser.add_argument("--ticks", type=int, default=1)
    args = parser.parse_args()

    if args.reset:
        state = generate_initial_state(args.units, args.machines_per_unit)
        STATE_FILE.write_text(json.dumps(state, indent=2, ensure_ascii=False), encoding="utf-8")
        print(f"Simulation reset: {len(state['units'])} units, {len(state['machines'])} machines", flush=True)
        return

    print("============================================================", flush=True)
    print("   VEXTHUB - SIMULADOR DE TELEMETRIA EM TEMPO REAL", flush=True)
    print("   Monitoramento Contínuo de Parque & Dispositivos", flush=True)
    print("============================================================", flush=True)
    print("[*] Carregando topologia e parque de máquinas...", flush=True)

    state = load_state()
    total_units = len(state.get("units", []))
    total_machines = len(state.get("machines", []))
    print(
        f"[OK] Parque carregado: {total_units} unidades ativas | "
        f"{total_machines} máquinas monitoradas.",
        flush=True,
    )
    print(
        f"[*] Iniciando streaming contínuo ({args.ticks} pulsos programados)...",
        flush=True,
    )
    print("-" * 60, flush=True)

    for tick in range(1, max(2, args.ticks + 1)):
        state = update_simulation(state)
        now_str = datetime.now().strftime("%H:%M:%S")
        events_count = len(state.get("events", []))

        print(
            f"[{now_str}] [PULSO #{tick:04d}] Telemetria ativa: "
            f"{total_units} unidades | "
            f"{total_machines} endpoints sincronizados | "
            f"{events_count} eventos em buffer",
            flush=True,
        )

        if args.ticks > 1:
            time.sleep(1.0)


if __name__ == "__main__":
    main()
