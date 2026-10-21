# -*- coding: utf-8 -*-
"""Local VextHub agent install simulation.

This runner does not modify Windows security settings. It consumes a read-only
host profile and simulates installer decisions, AV friction, privilege limits,
and telemetry registration inside simulation_state.json.
"""

from __future__ import annotations

import argparse
import json
import random
import re
import socket
import time
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
SCRATCH = ROOT / "scratch"
PROFILE_FILE = SCRATCH / "local-machine-profile.json"
STATUS_FILE = SCRATCH / "agent-install-simulation.json"
STATE_FILE = ROOT / "scripts" / "simulation_state.json"


def iso_now() -> str:
    return datetime.now().isoformat()


def read_json(path: Path, fallback: Any) -> Any:
    try:
      return json.loads(path.read_text(encoding="utf-8-sig"))
    except Exception:
      return fallback


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(value, indent=2, ensure_ascii=False), encoding="utf-8")
    tmp.replace(path)


class StatusWriter:
    def __init__(self, path: Path, profile: dict[str, Any], delay: int, unit: str):
        self.path = path
        self.status: dict[str, Any] = {
            "started_at": iso_now(),
            "updated_at": iso_now(),
            "phase": "scheduled",
            "delay_seconds": delay,
            "unit": unit,
            "profile_summary": summarize_profile(profile),
            "steps": [],
            "logs": [],
            "result": None,
        }
        self.flush()

    def flush(self) -> None:
        self.status["updated_at"] = iso_now()
        write_json(self.path, self.status)

    def log(self, level: str, message: str, **details: Any) -> None:
        entry = {
            "ts": iso_now(),
            "level": level,
            "message": message,
            "details": details,
        }
        self.status["logs"].append(entry)
        self.status["logs"] = self.status["logs"][-500:]
        self.flush()

    def step(self, name: str, outcome: str, message: str, **details: Any) -> None:
        entry = {
            "ts": iso_now(),
            "name": name,
            "outcome": outcome,
            "message": message,
            "details": details,
        }
        self.status["steps"].append(entry)
        self.status["logs"].append({
            "ts": entry["ts"],
            "level": outcome,
            "message": f"{name}: {message}",
            "details": details,
        })
        self.status["logs"] = self.status["logs"][-500:]
        self.flush()

    def phase(self, phase: str) -> None:
        self.status["phase"] = phase
        self.flush()


def summarize_profile(profile: dict[str, Any]) -> dict[str, Any]:
    security = profile.get("security_products") or []
    programs = profile.get("programs") or []
    drives = profile.get("drives") or []
    network = profile.get("network") or []
    hardware = profile.get("hardware") or {}
    os_data = profile.get("os") or {}

    return {
        "hostname": profile.get("hostname") or socket.gethostname(),
        "active_user": profile.get("active_user"),
        "is_admin_session": bool(profile.get("is_admin_session")),
        "os": os_data.get("caption"),
        "build": os_data.get("build_number"),
        "cpu": hardware.get("cpu"),
        "memory_gb": hardware.get("memory_gb"),
        "serial_number": hardware.get("serial_number"),
        "security_products": [item.get("name") for item in security if item.get("name")],
        "program_count": len(programs),
        "drive_count": len(drives),
        "network_adapter_count": len(network),
    }


def security_posture(profile: dict[str, Any]) -> dict[str, Any]:
    products = [str(item.get("name") or "").lower() for item in profile.get("security_products") or []]
    joined = " ".join(products)
    if "bitdefender" in joined:
        return {
            "vendor": "Bitdefender",
            "installer_trust": "medium",
            "tamper_protection": "strict",
            "service_creation": "admin_required",
            "exclusion_policy": "blocked_without_console_policy",
        }
    if "defender" in joined or "windows" in joined:
        return {
            "vendor": "Microsoft Defender",
            "installer_trust": "medium",
            "tamper_protection": "strict_if_enabled",
            "service_creation": "admin_required",
            "exclusion_policy": "requires_admin_and_policy",
        }
    if products:
        return {
            "vendor": profile.get("security_products", [{}])[0].get("name"),
            "installer_trust": "unknown",
            "tamper_protection": "unknown",
            "service_creation": "admin_required",
            "exclusion_policy": "vendor_policy_required",
        }
    return {
        "vendor": "Not reported",
        "installer_trust": "unknown",
        "tamper_protection": "unknown",
        "service_creation": "admin_required",
        "exclusion_policy": "unknown",
    }


SEVERITY_RANK = {
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


COMMAND_SURFACE_RULES: list[dict[str, Any]] = [
    {
        "id": "powershell-execution-policy-bypass",
        "source": "public/installer/instalar.bat",
        "patterns": ["ExecutionPolicy Bypass"],
        "surface": "launcher",
        "severity": "high",
        "category": "script-policy-bypass",
        "likely_classification": {
            "Bitdefender": "ATC/behavior review: PowerShell policy bypass",
            "Microsoft Defender": "Suspicious script execution / policy bypass",
            "Generic": "Potentially unwanted installer behavior",
        },
        "why": "PowerShell with ExecutionPolicy Bypass is a common loader pattern and hurts reputation even when the script is benign.",
        "recommendation": "Use a signed EXE/MSI or a signed PowerShell script under RemoteSigned/AllSigned. Do not include Bypass in production installers.",
        "certificate_effect": "partial",
    },
    {
        "id": "powershell-motw-unblock",
        "source": "public/installer/instalar.bat",
        "patterns": ["Unblock-File"],
        "surface": "launcher",
        "severity": "medium",
        "category": "mark-of-the-web-removal",
        "likely_classification": {
            "Bitdefender": "Installer script review: zone identifier removal",
            "Microsoft Defender": "Low-confidence suspicious script preparation",
            "Generic": "Installer reputation signal",
        },
        "why": "Removing Mark-of-the-Web can look like an attempt to reduce inspection friction.",
        "recommendation": "Distribute via signed installer package and let Windows trust/reputation handle origin.",
        "certificate_effect": "partial",
    },
    {
        "id": "legacy-scheduled-task-persistence",
        "source": "public/installer/install.ps1",
        "patterns": ["Register-ScheduledTask", "schtasks.exe /Create"],
        "surface": "persistence",
        "severity": "medium",
        "category": "scheduled-task-persistence",
        "likely_classification": {
            "Bitdefender": "ATC review: persistence via scheduled task",
            "Microsoft Defender": "Persistence behavior: scheduled task",
            "Generic": "Persistence mechanism requiring installer context",
        },
        "why": "Scheduled task creation is legitimate for management software, but is also a common malware persistence technique.",
        "recommendation": "Prefer a named signed Windows service or transparent HKCU Run entry, with installer UI and uninstall metadata.",
        "certificate_effect": "partial",
    },
    {
        "id": "legacy-hidden-launch",
        "source": "public/installer/install.ps1",
        "patterns": ["WindowStyle Minimized", "WindowStyle Hidden"],
        "surface": "process-launch",
        "severity": "medium",
        "category": "background-script-launch",
        "likely_classification": {
            "Bitdefender": "ATC review: background script execution",
            "Microsoft Defender": "Suspicious script launched in background",
            "Generic": "Potentially unwanted background execution",
        },
        "why": "Launching a script runner minimized/hidden can be interpreted as concealing activity.",
        "recommendation": "Launch the signed agent binary directly or keep installer progress visible.",
        "certificate_effect": "partial",
    },
    {
        "id": "static-obfuscation",
        "source": "src/installer/VextHubAgent.cs",
        "patterns": ["Decode(", "Base64 para confundir", "confundir analise estatica", "confundir an"],
        "surface": "static-analysis",
        "severity": "critical",
        "category": "obfuscation",
        "likely_classification": {
            "Bitdefender": "Gen/ATC review: obfuscated endpoint agent",
            "Microsoft Defender": "Suspicious obfuscation / evasive code",
            "Generic": "Trojan-like static traits",
        },
        "why": "String obfuscation around WMI, telemetry URLs, and security status looks like concealment.",
        "recommendation": "Keep endpoint, WMI namespace, product name, and startup identity as plain strings in signed builds.",
        "certificate_effect": "no",
    },
    {
        "id": "anti-sandbox-delay",
        "source": "src/installer/VextHubAgent.cs",
        "patterns": ["IsInSandbox", "Thread.Sleep(new Random().Next(120000, 180000))", "Anti-Sandbox"],
        "surface": "runtime-behavior",
        "severity": "critical",
        "category": "anti-analysis",
        "likely_classification": {
            "Bitdefender": "ATC: evasive behavior / sandbox evasion",
            "Microsoft Defender": "Behavior: anti-analysis delay",
            "Generic": "Malware-like sandbox evasion",
        },
        "why": "Detecting sandboxes or sleeping for minutes to outwait analysis is a strong malware signal.",
        "recommendation": "Remove sandbox checks and long randomized sleeps. Use normal telemetry intervals.",
        "certificate_effect": "no",
    },
    {
        "id": "browser-user-agent-masquerade",
        "source": "src/installer/VextHubAgent.cs",
        "patterns": ["Mozilla/5.0", "falsa legitimidade", "mimetizar navegadores"],
        "surface": "network",
        "severity": "high",
        "category": "network-masquerading",
        "likely_classification": {
            "Bitdefender": "ATC review: network masquerading",
            "Microsoft Defender": "Suspicious network client impersonation",
            "Generic": "C2-like client masquerading",
        },
        "why": "A security agent pretending to be Chrome/Edge/Firefox resembles commodity malware network camouflage.",
        "recommendation": "Use a stable User-Agent such as VextHubAgent/<version> and explicit product headers.",
        "certificate_effect": "no",
    },
    {
        "id": "hidden-system-file-attribute",
        "source": "src/installer/VextHubAgent.cs",
        "patterns": ["SetFileAttributes", "FILE_ATTRIBUTE_HIDDEN", "FILE_ATTRIBUTE_SYSTEM"],
        "surface": "filesystem",
        "severity": "high",
        "category": "file-concealment",
        "likely_classification": {
            "Bitdefender": "ATC: hidden/system attribute on executable",
            "Microsoft Defender": "Suspicious file concealment",
            "Generic": "Concealment behavior",
        },
        "why": "Marking the agent executable hidden/system is a concealment signal.",
        "recommendation": "Keep files visible in a named vendor directory with normal permissions.",
        "certificate_effect": "no",
    },
    {
        "id": "windows-update-masquerade-startup",
        "source": "src/installer/VextHubAgent.cs",
        "patterns": ["WindowsUpdateHealthConf", "InternetShortcut", ".url"],
        "surface": "persistence",
        "severity": "high",
        "category": "masqueraded-startup",
        "likely_classification": {
            "Bitdefender": "ATC: startup masquerading",
            "Microsoft Defender": "Persistence using misleading name",
            "Generic": "Masqueraded persistence",
        },
        "why": "Using a Windows Update-like name and .url startup indirection makes the agent look intentionally disguised.",
        "recommendation": "Use the real product name in HKCU Run, a Windows service, or MSI uninstall metadata.",
        "certificate_effect": "no",
    },
    {
        "id": "remote-command-channel",
        "source": "src/installer/VextHubAgent.cs",
        "patterns": ["ProcessAgentCommands", "ExecuteCommand", "\"commands\""],
        "surface": "command-channel",
        "severity": "medium",
        "category": "remote-command-control",
        "likely_classification": {
            "Bitdefender": "EDR review: remote management command channel",
            "Microsoft Defender": "Remote management behavior requiring allowlist",
            "Generic": "Dual-use RMM capability",
        },
        "why": "Polling and executing server commands is normal for an RMM/EDR agent, but must be tightly scoped and audited.",
        "recommendation": "Keep an explicit allowlist, signed command payloads, audit logging, and clear product identity.",
        "certificate_effect": "partial",
    },
]


def read_text_optional(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8-sig", errors="ignore")
    except Exception:
        return ""


def executable_surface_text(text: str, source: str) -> str:
    if source.endswith(".cs"):
        text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
        return "\n".join(line for line in text.splitlines() if not line.strip().startswith("//"))
    if source.endswith(".ps1"):
        return "\n".join(line for line in text.splitlines() if not line.strip().startswith("#"))
    if source.endswith(".bat") or source.endswith(".cmd"):
        return "\n".join(
            line for line in text.splitlines()
            if not line.strip().lower().startswith(("::", "rem "))
        )
    return text


def matching_line(text: str, patterns: list[str]) -> int | None:
    lowered_patterns = [item.lower() for item in patterns]
    for index, line in enumerate(text.splitlines(), start=1):
        lowered = line.lower()
        if any(pattern in lowered for pattern in lowered_patterns):
            return index
    return None


def analyze_command_surface() -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for rule in COMMAND_SURFACE_RULES:
        source = str(rule["source"])
        source_path = ROOT / source
        raw_text = read_text_optional(source_path)
        text = executable_surface_text(raw_text, source)
        patterns = [str(item) for item in rule["patterns"]]
        lowered = text.lower()
        matched = [item for item in patterns if item.lower() in lowered]
        if not matched:
            continue
        findings.append({
            "id": rule["id"],
            "source": source,
            "line": matching_line(raw_text, matched),
            "surface": rule["surface"],
            "severity": rule["severity"],
            "category": rule["category"],
            "matched_patterns": matched,
            "likely_classification": rule["likely_classification"],
            "why": rule["why"],
            "recommendation": rule["recommendation"],
            "certificate_effect": rule["certificate_effect"],
        })
    findings.sort(key=lambda item: SEVERITY_RANK.get(item["severity"], 0), reverse=True)
    return findings


def summarize_command_findings(findings: list[dict[str, Any]], posture: dict[str, Any], signed_installer: bool) -> dict[str, Any]:
    vendor = str(posture.get("vendor") or "Generic")
    vendor_key = vendor if vendor in {"Bitdefender", "Microsoft Defender"} else "Generic"
    max_severity = "info"
    categories: dict[str, int] = {}
    certificate_limited = 0
    certificate_no_effect = 0
    likely_labels: list[str] = []

    for finding in findings:
        severity = str(finding.get("severity") or "info")
        if SEVERITY_RANK.get(severity, 0) > SEVERITY_RANK.get(max_severity, 0):
            max_severity = severity
        category = str(finding.get("category") or "unknown")
        categories[category] = categories.get(category, 0) + 1
        if finding.get("certificate_effect") == "partial":
            certificate_limited += 1
        if finding.get("certificate_effect") == "no":
            certificate_no_effect += 1
        classifications = finding.get("likely_classification") or {}
        label = classifications.get(vendor_key) or classifications.get("Generic")
        if label and label not in likely_labels:
            likely_labels.append(label)

    blocking = [
        finding["id"]
        for finding in findings
        if SEVERITY_RANK.get(str(finding.get("severity")), 0) >= SEVERITY_RANK["high"]
    ]
    verdict = "clean"
    if blocking:
        verdict = "blocked_or_quarantined"
    elif findings:
        verdict = "review_required"

    if signed_installer and findings:
        signing_effect = (
            "Certificate improves publisher trust, but it does not neutralize behavioral detections."
            if certificate_no_effect
            else "Certificate can reduce reputation friction, but EDR review is still required."
        )
    elif signed_installer:
        signing_effect = "Certificate should improve trust for this behavior surface."
    else:
        signing_effect = "Unsigned build has weaker reputation; certificate should be evaluated after behavioral cleanup."

    return {
        "vendor": vendor,
        "verdict": verdict,
        "max_severity": max_severity,
        "finding_count": len(findings),
        "blocking_finding_ids": blocking,
        "categories": categories,
        "likely_labels": likely_labels[:8],
        "certificate_limited_findings": certificate_limited,
        "certificate_no_effect_findings": certificate_no_effect,
        "signed_installer": signed_installer,
        "signing_effect": signing_effect,
    }


def normalize_program(item: dict[str, Any]) -> dict[str, Any]:
    return {
        "name": item.get("name") or item.get("DisplayName") or "Unknown Program",
        "version": item.get("version") or item.get("DisplayVersion") or "",
        "publisher": item.get("publisher") or item.get("Publisher") or "",
        "install_date": item.get("install_date") or "",
    }


def machine_id_from_profile(profile: dict[str, Any], unit: str) -> str:
    hostname = str(profile.get("hostname") or socket.gethostname()).upper()
    cleaned = "".join(ch for ch in hostname if ch.isalnum())[-10:] or "LOCALHOST"
    return f"{unit}-HOST-{cleaned}"


def build_machine(profile: dict[str, Any], unit: str, result: dict[str, Any]) -> dict[str, Any]:
    summary = summarize_profile(profile)
    programs = [normalize_program(item) for item in (profile.get("programs") or [])]
    security_products = profile.get("security_products") or []
    network = profile.get("network") or []
    drives = profile.get("drives") or []
    primary_drive = drives[0] if drives else {}
    primary_ip = "0.0.0.0"
    if network and isinstance(network[0].get("ip"), list) and network[0]["ip"]:
        primary_ip = str(network[0]["ip"][0])

    machine_id = machine_id_from_profile(profile, unit)
    disk_total = int(float(primary_drive.get("size_gb") or 512))
    disk_free = int(float(primary_drive.get("free_gb") or 256))
    disk_used_pct = 100 - round((disk_free / max(1, disk_total)) * 100)

    return {
        "id": machine_id,
        "hostname": summary["hostname"],
        "ip": primary_ip,
        "unit": unit,
        "status": "online",
        "last_pulse": iso_now(),
        "os_name": summary.get("os"),
        "cpu_info": summary.get("cpu"),
        "ram_total": f"{summary.get('memory_gb') or 0}GB",
        "serial_number": summary.get("serial_number") or f"SIM-{uuid.uuid4().hex[:12].upper()}",
        "agent_version": "4.1.0-sim-install",
        "inventory_data": {
            "software": programs,
            "security_products": security_products,
            "install_simulation": result,
            "av_edr_detection": result.get("detection_summary", {}),
            "system_details": {
                "active_user": summary.get("active_user"),
                "local_ip": primary_ip,
                "disk_total_gb": disk_total,
                "disk_free_gb": disk_free,
                "domain": f"VEXT-{unit}",
            },
            "processes": [
                {"name": "VextHubAgent.exe", "cpu": 0.4, "simulated": True},
                {"name": "MsMpEng.exe", "cpu": 1.1, "simulated": True},
            ],
            "services": [
                {
                    "name": "VextHubAgent",
                    "state": "Running" if result["service_mode"] == "windows_service" else "NotInstalled",
                    "start_mode": result["service_mode"],
                    "simulated": True,
                }
            ],
            "startup_entries": result.get("startup_entries", []),
        },
        "telemetry": {
            "cpu": random.randint(8, 35),
            "ram": random.randint(25, 70),
            "disk": max(1, min(99, disk_used_pct)),
        },
    }


def inject_machine(profile: dict[str, Any], unit: str, result: dict[str, Any]) -> str:
    state = read_json(STATE_FILE, {"units": [], "machines": [], "events": [], "agent_commands": []})
    state.setdefault("units", [])
    state.setdefault("machines", [])
    state.setdefault("events", [])
    state.setdefault("agent_commands", [])

    if not any(unit_item.get("id") == unit for unit_item in state["units"]):
        state["units"].append({
            "id": unit,
            "name": "VEXT Local Install Lab",
            "city": "Local",
            "state": "LAB",
            "location": "Local, LAB",
            "lat": -23.5505,
            "lon": -46.6333,
            "agent_key": "v_key_local_install_lab",
            "network_assets": [],
        })

    machine = build_machine(profile, unit, result)
    existing_index = next((idx for idx, item in enumerate(state["machines"]) if item.get("id") == machine["id"]), None)
    if existing_index is None:
        state["machines"].insert(0, machine)
    else:
        state["machines"][existing_index] = {**state["machines"][existing_index], **machine}

    severity = "MEDIUM" if result["final_status"] == "degraded" else "LOW"
    state["events"].insert(0, {
        "id": f"EVT-INSTALL-{uuid.uuid4().hex[:10]}",
        "timestamp": iso_now(),
        "agent_hostname": machine["hostname"],
        "unit": unit,
        "severity": severity,
        "type": "VextHub Agent install simulation completed",
        "description": result["summary"],
        "details": {
            "machine_id": machine["id"],
            "final_status": result["final_status"],
            "security_vendor": result["security_posture"]["vendor"],
            "blocked_steps": result["blocked_steps"],
            "needs_admin_steps": result["needs_admin_steps"],
            "av_edr_verdict": result.get("detection_summary", {}).get("verdict"),
            "av_edr_max_severity": result.get("detection_summary", {}).get("max_severity"),
            "av_edr_finding_count": result.get("detection_summary", {}).get("finding_count"),
        },
    })
    state["events"] = state["events"][:1000]
    write_json(STATE_FILE, state)
    return machine["id"]


def run_install(profile: dict[str, Any], status: StatusWriter, unit: str, signed_installer: bool) -> dict[str, Any]:
    posture = security_posture(profile)
    is_admin = bool(profile.get("is_admin_session"))
    command_findings = analyze_command_surface()
    detection_summary = summarize_command_findings(command_findings, posture, signed_installer)
    blocked_steps: list[str] = []
    needs_admin_steps: list[str] = []
    startup_entries: list[dict[str, Any]] = []

    status.phase("running")
    status.log("info", "Read-only host profile loaded", profile=summarize_profile(profile))
    time.sleep(0.8)

    status.step("Pre-flight", "ok", "Installer manifest and local host profile validated", vendor=posture["vendor"])
    time.sleep(0.8)
    if signed_installer:
        status.step("Signature policy", "ok", "VextHub package treated as signed by a trusted publisher")
    else:
        status.step("Signature policy", "av_review", "Unsigned or development package requires reputation review")
    time.sleep(0.8)

    if command_findings:
        outcome = "blocked" if detection_summary["verdict"] == "blocked_or_quarantined" else "av_review"
        if outcome == "blocked":
            blocked_steps.append("AV/EDR behavior classification")
        status.step(
            "AV/EDR command review",
            outcome,
            (
                f"{detection_summary['finding_count']} command/behavior signal(s) found; "
                f"highest severity: {detection_summary['max_severity']}"
            ),
            likely_labels=detection_summary["likely_labels"],
            blocking_finding_ids=detection_summary["blocking_finding_ids"],
        )
    else:
        status.step("AV/EDR command review", "ok", "No suspicious installer or agent command patterns found")
    time.sleep(0.8)

    if is_admin:
        status.step("Install path", "ok", "C:\\Program Files\\VextHub is writable for elevated installer context")
        service_mode = "windows_service"
    else:
        needs_admin_steps.append("Install path")
        status.step("Install path", "needs_admin", "Program Files install requires elevation; simulated fallback selected")
        service_mode = "user_mode"
    time.sleep(0.8)

    if posture["vendor"] in {"Bitdefender", "Microsoft Defender"}:
        blocked_steps.append("Security exclusion")
        status.step(
            "Security exclusion",
            "blocked",
            f"{posture['vendor']} policy would not allow installer-side exclusion changes",
            tamper_protection=posture["tamper_protection"],
        )
    else:
        status.step("Security exclusion", "av_review", "Security product requires central policy review; no local bypass attempted")
    time.sleep(0.8)

    if is_admin:
        status.step("Service registration", "ok", "Windows service registration would be allowed in elevated context")
    else:
        needs_admin_steps.append("Service registration")
        status.step("Service registration", "needs_admin", "SCM service creation requires elevation; user-mode agent channel selected")
    time.sleep(0.8)

    startup_entries.append({
        "name": "VextHubAgent",
        "path": "%LOCALAPPDATA%\\VextHub\\VextHubAgent.exe",
        "mode": service_mode,
        "simulated": True,
    })
    status.step("Startup fallback", "ok", "User-mode startup registration simulated without writing registry keys")
    time.sleep(0.8)
    status.step("Telemetry bootstrap", "ok", "Agent identity, inventory snapshot and command polling channel prepared")
    time.sleep(0.8)

    final_status = "degraded" if blocked_steps or needs_admin_steps else "ready"
    summary = (
        "Agent simulated as online with limited install posture: "
        f"{len(blocked_steps)} AV/policy block(s), {len(needs_admin_steps)} admin-gated step(s)."
        if final_status == "degraded"
        else "Agent simulated as fully installed and online."
    )
    result = {
        "final_status": final_status,
        "summary": summary,
        "service_mode": service_mode,
        "security_posture": posture,
        "detection_summary": detection_summary,
        "command_findings": command_findings,
        "blocked_steps": blocked_steps,
        "needs_admin_steps": needs_admin_steps,
        "startup_entries": startup_entries,
    }

    machine_id = inject_machine(profile, unit, result)
    result["machine_id"] = machine_id
    status.step("VextHub registration", "ok", "Simulated machine injected into local fleet", machine_id=machine_id)
    status.phase("completed")
    status.status["result"] = result
    status.flush()
    return result


def default_profile() -> dict[str, Any]:
    return {
        "generated_at": iso_now(),
        "collection_mode": "fallback",
        "hostname": socket.gethostname(),
        "active_user": None,
        "is_admin_session": False,
        "os": {"caption": "Windows workstation"},
        "hardware": {"cpu": "Unknown CPU", "memory_gb": 0, "serial_number": None},
        "security_products": [],
        "drives": [],
        "network": [],
        "programs": [],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Simulate a real-world VextHub agent install after a delay.")
    parser.add_argument("--delay", type=int, default=120)
    parser.add_argument("--profile", default=str(PROFILE_FILE))
    parser.add_argument("--status", default=str(STATUS_FILE))
    parser.add_argument("--unit", default="UN-LAB")
    parser.add_argument(
        "--signed-installer",
        action="store_true",
        help="Treat the package as code-signed to show what certificate trust does and does not change.",
    )
    args = parser.parse_args()

    profile = read_json(Path(args.profile), default_profile())
    status = StatusWriter(Path(args.status), profile, args.delay, args.unit)

    if args.delay > 0:
        status.phase("countdown")
        for remaining in range(args.delay, 0, -1):
            if remaining == args.delay or remaining <= 10 or remaining % 15 == 0:
                status.log("info", "Waiting for scheduled install window", seconds_remaining=remaining)
            time.sleep(1)

    run_install(profile, status, args.unit, args.signed_installer)
    print(f"Agent install simulation completed: {args.status}")


if __name__ == "__main__":
    main()
