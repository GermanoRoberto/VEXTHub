import json
from typing import Any, Dict, List


class SigmaLiteEngine:
    def __init__(self) -> None:
        self.rules = [
            {
                "id": "rat-rustdesk",
                "title": "RustDesk remote access tool detected",
                "severity": "HIGH",
                "score": 70,
                "tactic": "Command and Control",
                "technique": "T1219",
                "aliases": ["rustdesk"],
            },
            {
                "id": "rat-ultraviewer",
                "title": "UltraViewer remote access tool detected",
                "severity": "HIGH",
                "score": 75,
                "tactic": "Command and Control",
                "technique": "T1219",
                "aliases": ["ultraviewer", "ultra viewer"],
            },
            {
                "id": "rat-supremo",
                "title": "Supremo remote access tool detected",
                "severity": "HIGH",
                "score": 75,
                "tactic": "Command and Control",
                "technique": "T1219",
                "aliases": ["supremo"],
            },
            {
                "id": "rat-ammyy",
                "title": "Ammyy Admin remote access tool detected",
                "severity": "CRITICAL",
                "score": 90,
                "tactic": "Command and Control",
                "technique": "T1219",
                "aliases": ["ammyy"],
            },
            {
                "id": "rat-dwservice",
                "title": "DWService remote access agent detected",
                "severity": "HIGH",
                "score": 78,
                "tactic": "Command and Control",
                "technique": "T1219",
                "aliases": ["dwservice", "dwagent"],
            },
            {
                "id": "rat-anydesk",
                "title": "AnyDesk remote access tool detected",
                "severity": "MEDIUM",
                "score": 45,
                "tactic": "Command and Control",
                "technique": "T1219",
                "aliases": ["anydesk"],
            },
            {
                "id": "rat-screenconnect",
                "title": "ConnectWise ScreenConnect detected",
                "severity": "MEDIUM",
                "score": 55,
                "tactic": "Command and Control",
                "technique": "T1219",
                "aliases": ["screenconnect", "connectwise control"],
            },
            {
                "id": "lolbin-powershell-encoded",
                "title": "PowerShell encoded command indicator",
                "severity": "HIGH",
                "score": 75,
                "tactic": "Execution",
                "technique": "T1059.001",
                "aliases": ["powershell -enc", "encodedcommand"],
            },
            {
                "id": "lolbin-regsvr32-scriptlet",
                "title": "Regsvr32 scriptlet execution indicator",
                "severity": "CRITICAL",
                "score": 90,
                "tactic": "Defense Evasion",
                "technique": "T1218.010",
                "aliases": ["regsvr32", "scrobj.dll", "/i:http"],
            },
            {
                "id": "impact-shadow-delete",
                "title": "Shadow copy deletion indicator",
                "severity": "CRITICAL",
                "score": 95,
                "tactic": "Impact",
                "technique": "T1490",
                "aliases": ["vssadmin delete shadows", "wmic shadowcopy delete"],
            },
        ]

    def scan(self, telemetry: Dict[str, Any]) -> List[Dict[str, Any]]:
        text = json.dumps(telemetry, ensure_ascii=False).lower()
        matches: List[Dict[str, Any]] = []
        for rule in self.rules:
            if any(alias in text for alias in rule["aliases"]):
                matches.append(
                    {
                        "id": rule["id"],
                        "rule": rule["title"],
                        "severity": rule["severity"],
                        "score": rule["score"],
                        "tactic": rule["tactic"],
                        "technique": rule["technique"],
                    }
                )
        return sorted(matches, key=lambda item: int(item["score"]), reverse=True)


detection_engine = SigmaLiteEngine()
