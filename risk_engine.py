"""Risk scoring helpers for NetSentinel.

This module intentionally uses a simple, explainable risk model suitable for a
student CV project. It is inspired by common exposure severity ideas, not a full
CVSS implementation.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class RiskResult:
    level: str
    score: int
    reason: str


CRITICAL_PORTS = {
    23: "Telnet is unencrypted and should not be exposed.",
    445: "SMB exposure can indicate high lateral movement risk.",
    5900: "VNC exposure may allow remote desktop access.",
}

HIGH_PORTS = {
    21: "FTP may expose credentials or files if misconfigured.",
    3306: "MySQL database service should not be publicly exposed.",
    5432: "PostgreSQL database service should not be publicly exposed.",
    3389: "RDP exposure can create remote access risk.",
    6379: "Redis exposure can lead to unauthorized data access.",
    9200: "Elasticsearch exposure can leak indexed data.",
}

MEDIUM_PORTS = {
    22: "SSH should be restricted and protected with strong authentication.",
    25: "SMTP exposure may be abused if misconfigured.",
    53: "DNS service should be monitored for misconfiguration.",
    80: "HTTP is unencrypted; HTTPS is preferred.",
    110: "POP3 is often legacy and may be insecure.",
    143: "IMAP should be secured with TLS.",
    8080: "Alternative HTTP service should be reviewed.",
}

LOW_PORTS = {
    443: "HTTPS is expected, but certificate and configuration should be reviewed.",
}


def classify_risk(port: int, service: str = "") -> RiskResult:
    """Return a simple risk level for a detected open port."""
    service_l = (service or "").lower()

    if port in CRITICAL_PORTS:
        return RiskResult("Critical", 95, CRITICAL_PORTS[port])
    if port in HIGH_PORTS:
        return RiskResult("High", 80, HIGH_PORTS[port])
    if port in MEDIUM_PORTS:
        return RiskResult("Medium", 55, MEDIUM_PORTS[port])
    if port in LOW_PORTS:
        return RiskResult("Low", 25, LOW_PORTS[port])

    if any(word in service_l for word in ["telnet", "vnc"]):
        return RiskResult("Critical", 90, "Remote or unencrypted service detected.")
    if any(word in service_l for word in ["mysql", "postgres", "redis", "rdp", "smb"]):
        return RiskResult("High", 75, "Sensitive service type detected.")
    if any(word in service_l for word in ["ssh", "ftp", "http"]):
        return RiskResult("Medium", 50, "Common network service detected; access should be reviewed.")

    return RiskResult("Info", 10, "No high-risk pattern matched; monitor for changes.")
