"""Core scanning, baseline comparison and report generation for NetSentinel."""
from __future__ import annotations

import ipaddress
import json
import os
import re
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Tuple

from risk_engine import classify_risk

try:
    import nmap  # type: ignore
except Exception:  # pragma: no cover - handled at runtime
    nmap = None

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
REPORTS_DIR = BASE_DIR / "reports"
BASELINE_FILE = DATA_DIR / "baseline.json"

DATA_DIR.mkdir(exist_ok=True)
REPORTS_DIR.mkdir(exist_ok=True)

ScanDict = Dict[str, Dict[str, Dict[str, Dict[str, Any]]]]


def validate_target(target: str) -> str:
    """Validate a basic IPv4, CIDR, localhost or simple hostname target."""
    target = (target or "").strip()
    if not target:
        raise ValueError("Hedef IP/subnet boş olamaz.")

    if target == "localhost":
        return target

    try:
        if "/" in target:
            ipaddress.ip_network(target, strict=False)
        else:
            ipaddress.ip_address(target)
        return target
    except ValueError:
        pass

    if re.fullmatch(r"[a-zA-Z0-9.-]{1,253}", target):
        return target

    raise ValueError("Geçersiz hedef. Örnek: 127.0.0.1 veya 192.168.1.0/24")


def load_baseline() -> ScanDict:
    if not BASELINE_FILE.exists():
        return {}
    try:
        with BASELINE_FILE.open("r", encoding="utf-8") as file:
            return json.load(file)
    except json.JSONDecodeError:
        return {}


def save_baseline(scan_data: ScanDict) -> None:
    with BASELINE_FILE.open("w", encoding="utf-8") as file:
        json.dump(scan_data, file, indent=4, ensure_ascii=False)


def _demo_scan() -> ScanDict:
    """Return sample data so the web UI can be demonstrated without Nmap."""
    sample = {
        "127.0.0.1": {
            "tcp": {
                "22": {"service": "ssh", "state": "open", "product": "OpenSSH", "version": "demo"},
                "80": {"service": "http", "state": "open", "product": "Demo HTTP", "version": "1.0"},
                "3306": {"service": "mysql", "state": "open", "product": "MySQL", "version": "demo"},
            }
        }
    }
    return _attach_risk(sample)


def _attach_risk(scan: ScanDict) -> ScanDict:
    for host_data in scan.values():
        for proto_data in host_data.values():
            for port_str, details in proto_data.items():
                risk = classify_risk(int(port_str), details.get("service", ""))
                details["risk"] = risk.level
                details["risk_score"] = risk.score
                details["risk_reason"] = risk.reason
    return scan


def run_nmap_scan(target: str, arguments: str = "-F -sV") -> Tuple[ScanDict, str | None]:
    """Run an Nmap scan and return structured results.

    Returns a tuple: (scan_data, warning). If Nmap is unavailable, demo data is
    returned with a warning so the dashboard is still presentable.
    """
    target = validate_target(target)

    if nmap is None:
        return _demo_scan(), "python-nmap paketi bulunamadı; demo veri gösteriliyor."

    try:
        scanner = nmap.PortScanner()
        scanner.scan(hosts=target, arguments=arguments)
    except Exception as exc:
        return _demo_scan(), f"Nmap çalıştırılamadı ({exc}); demo veri gösteriliyor."

    current_scan: ScanDict = {}
    for host in scanner.all_hosts():
        current_scan[host] = {}
        for proto in scanner[host].all_protocols():
            current_scan[host][proto] = {}
            for port in sorted(scanner[host][proto].keys()):
                port_info = scanner[host][proto][port]
                service = port_info.get("name", "unknown")
                current_scan[host][proto][str(port)] = {
                    "service": service,
                    "state": port_info.get("state", "unknown"),
                    "product": port_info.get("product", ""),
                    "version": port_info.get("version", ""),
                }

    return _attach_risk(current_scan), None


def compare_with_baseline(current: ScanDict, baseline: ScanDict) -> List[Dict[str, str]]:
    """Detect new hosts, protocols and ports compared to baseline."""
    alerts: List[Dict[str, str]] = []

    for host, protocols in current.items():
        if host not in baseline:
            alerts.append({
                "severity": "High",
                "message": f"Yeni cihaz tespit edildi: {host}",
            })
            continue

        for proto, ports in protocols.items():
            if proto not in baseline[host]:
                alerts.append({
                    "severity": "Medium",
                    "message": f"Bilinen cihazda yeni protokol tespit edildi: {host} / {proto.upper()}",
                })
                continue

            for port, details in ports.items():
                if port not in baseline[host][proto]:
                    alerts.append({
                        "severity": details.get("risk", "Medium"),
                        "message": (
                            f"Bilinen cihazda yeni açık port tespit edildi: "
                            f"{host}:{port}/{proto} - {details.get('service', 'unknown')}"
                        ),
                    })

    return alerts


def flatten_findings(scan_data: ScanDict) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    for host, protocols in scan_data.items():
        for proto, ports in protocols.items():
            for port, details in ports.items():
                findings.append({
                    "host": host,
                    "protocol": proto,
                    "port": int(port),
                    "service": details.get("service", "unknown"),
                    "state": details.get("state", "unknown"),
                    "product": details.get("product", ""),
                    "version": details.get("version", ""),
                    "risk": details.get("risk", "Info"),
                    "risk_score": details.get("risk_score", 0),
                    "risk_reason": details.get("risk_reason", ""),
                })
    return sorted(findings, key=lambda item: (item["host"], item["port"]))


def summarize(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    hosts = {item["host"] for item in findings}
    return {
        "total_hosts": len(hosts),
        "total_open_ports": len(findings),
        "critical_count": sum(1 for item in findings if item["risk"] == "Critical"),
        "high_count": sum(1 for item in findings if item["risk"] == "High"),
        "medium_count": sum(1 for item in findings if item["risk"] == "Medium"),
        "low_count": sum(1 for item in findings if item["risk"] == "Low"),
        "info_count": sum(1 for item in findings if item["risk"] == "Info"),
    }


def create_report(target: str, findings: List[Dict[str, Any]], alerts: List[Dict[str, str]], summary: Dict[str, Any]) -> str:
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    filename = f"netsentinel_report_{timestamp}.txt"
    report_path = REPORTS_DIR / filename

    with report_path.open("w", encoding="utf-8") as file:
        file.write("[NetSentinel Güvenlik Raporu]\n")
        file.write(f"Tarih: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        file.write(f"Hedef: {target}\n")
        file.write("-" * 60 + "\n")
        file.write(f"Toplam Host: {summary['total_hosts']}\n")
        file.write(f"Açık Port: {summary['total_open_ports']}\n")
        file.write(f"Kritik Risk: {summary['critical_count']}\n")
        file.write(f"Yüksek Risk: {summary['high_count']}\n")
        file.write("-" * 60 + "\n\n")

        file.write("[Bulgular]\n")
        for finding in findings:
            file.write(
                f"{finding['host']}:{finding['port']}/{finding['protocol']} "
                f"{finding['service']} | Risk: {finding['risk']} | {finding['risk_reason']}\n"
            )

        file.write("\n[Baseline Alarmları]\n")
        if alerts:
            for alert in alerts:
                file.write(f"[{alert['severity']}] {alert['message']}\n")
        else:
            file.write("Anomali tespit edilmedi.\n")

    return filename


def perform_scan(target: str, arguments: str = "-F -sV") -> Dict[str, Any]:
    """Run scan, compare with baseline, produce report-ready output."""
    target = validate_target(target)
    started_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    baseline = load_baseline()
    scan_data, warning = run_nmap_scan(target, arguments=arguments)
    baseline_created = False

    if not baseline:
        save_baseline(scan_data)
        baseline = scan_data
        baseline_created = True

    findings = flatten_findings(scan_data)
    alerts = [] if baseline_created else compare_with_baseline(scan_data, baseline)
    summary = summarize(findings)
    report_filename = create_report(target, findings, alerts, summary)

    return {
        "target": target,
        "arguments": arguments,
        "started_at": started_at,
        "baseline_created": baseline_created,
        "warning": warning,
        "scan_data": scan_data,
        "findings": findings,
        "alerts": alerts,
        "summary": summary,
        "report_filename": report_filename,
    }
