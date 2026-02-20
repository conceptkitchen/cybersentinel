"""Mock Datadog MCP Server for CyberSentinel.

Provides realistic security telemetry without requiring a real Datadog account.
Run standalone: python mock_datadog_mcp.py
Or used automatically by CyberSentinel agents via Strands MCPClient.
"""

import json
import random
from datetime import datetime, timedelta
from typing import Optional

from fastmcp import FastMCP

mcp = FastMCP("CyberSentinel Datadog MCP")

# Simulated infrastructure
SERVICES = [
    "payment-api", "auth-service", "user-db", "api-gateway",
    "inventory-service", "notification-service", "cdn-edge",
]
ENVS = ["prod", "staging"]
HOSTS = [
    "prod-web-01", "prod-web-02", "prod-db-01", "prod-db-02",
    "prod-api-01", "prod-api-02", "staging-web-01",
]

# Pre-built security-focused monitors
MONITORS = [
    {
        "id": 1001,
        "name": "[SECURITY] Brute Force Detection - Auth Service",
        "status": "Alert",
        "type": "metric alert",
        "service": "auth-service",
        "env": "prod",
        "query": "sum(last_5m):sum:auth.login.failed{service:auth-service} > 500",
        "message": "Over 500 failed login attempts in 5 minutes. Possible brute force attack.",
        "tags": ["security", "brute-force", "auth"],
        "priority": "P1",
    },
    {
        "id": 1002,
        "name": "[SECURITY] Unusual Data Transfer - User DB",
        "status": "Alert",
        "type": "metric alert",
        "service": "user-db",
        "env": "prod",
        "query": "avg(last_10m):sum:aws.s3.bytes_downloaded{bucket:prod-user-data} > 5000000000",
        "message": "Anomalous data transfer detected. 5GB+ downloaded from user-data bucket in 10 min.",
        "tags": ["security", "data-exfiltration", "s3"],
        "priority": "P1",
    },
    {
        "id": 1003,
        "name": "[SECURITY] Ransomware Indicators - File Encryption",
        "status": "Alert",
        "type": "log alert",
        "service": "user-db",
        "env": "prod",
        "query": "logs(\"source:sysmon encryption OR .encrypted OR ransom\").index(\"*\").rollup(\"count\").last(\"5m\") > 100",
        "message": "Mass file encryption activity detected. 100+ encrypted files in 5 min. RANSOMWARE LIKELY.",
        "tags": ["security", "ransomware", "critical"],
        "priority": "P1",
    },
    {
        "id": 1004,
        "name": "[INFRA] High CPU - API Gateway",
        "status": "Warn",
        "type": "metric alert",
        "service": "api-gateway",
        "env": "prod",
        "query": "avg(last_15m):avg:system.cpu.user{service:api-gateway} > 85",
        "message": "API Gateway CPU consistently above 85%. May indicate DDoS or resource exhaustion.",
        "tags": ["infrastructure", "cpu", "api-gateway"],
        "priority": "P2",
    },
    {
        "id": 1005,
        "name": "[SECURITY] IAM Privilege Escalation",
        "status": "Alert",
        "type": "log alert",
        "service": "auth-service",
        "env": "prod",
        "query": "logs(\"source:cloudtrail CreateUser OR AttachUserPolicy OR AssumeRole\").rollup(\"count\").last(\"5m\") > 5",
        "message": "Multiple IAM modifications detected in short window. Possible privilege escalation.",
        "tags": ["security", "iam", "privilege-escalation"],
        "priority": "P1",
    },
    {
        "id": 1006,
        "name": "[SECURITY] Outbound C2 Communication",
        "status": "Alert",
        "type": "log alert",
        "service": "user-db",
        "env": "prod",
        "query": "logs(\"source:vpc-flow-logs destination:185.234.219.0/24\").rollup(\"count\").last(\"10m\") > 0",
        "message": "Outbound connections to known C2 infrastructure detected from prod-db-01.",
        "tags": ["security", "c2", "malware"],
        "priority": "P1",
    },
    {
        "id": 1007,
        "name": "[INFRA] Disk Space Critical - DB Servers",
        "status": "OK",
        "type": "metric alert",
        "service": "user-db",
        "env": "prod",
        "query": "avg(last_30m):avg:system.disk.in_use{service:user-db} > 0.90",
        "message": "Database server disk usage above 90%.",
        "tags": ["infrastructure", "disk", "database"],
        "priority": "P3",
    },
    {
        "id": 1008,
        "name": "[SECURITY] Port Scan Detection",
        "status": "Warn",
        "type": "log alert",
        "service": "api-gateway",
        "env": "prod",
        "query": "logs(\"source:guardduty Recon:EC2/PortProbeUnprotectedPort\").rollup(\"count\").last(\"15m\") > 0",
        "message": "GuardDuty detected port scanning activity targeting production instances.",
        "tags": ["security", "recon", "port-scan"],
        "priority": "P2",
    },
]

INCIDENTS = [
    {
        "id": "INC-2026-0042",
        "title": "Active Ransomware Attack - Production Database",
        "severity": "SEV-1",
        "status": "active",
        "created": (datetime.utcnow() - timedelta(minutes=45)).isoformat() + "Z",
        "services": ["user-db", "payment-api"],
        "commander": "soc-team@company.com",
        "timeline": [
            {"time": "-45m", "event": "GuardDuty alert: Unusual process execution on prod-db-01"},
            {"time": "-42m", "event": "Sysmon: Mass file rename activity (.encrypted extension)"},
            {"time": "-40m", "event": "Network: Outbound connection to 185.234.219.8:443 (known C2)"},
            {"time": "-38m", "event": "CloudTrail: S3 DeleteObject burst on backup bucket"},
            {"time": "-35m", "event": "Monitor INC-1003 triggered: Ransomware indicators"},
            {"time": "-30m", "event": "Incident declared SEV-1. SOC team paged."},
            {"time": "-25m", "event": "Network isolation initiated for prod-db-01"},
            {"time": "-20m", "event": "Forensic snapshot of affected EBS volumes initiated"},
        ],
        "iocs": [
            {"type": "ip", "value": "185.234.219.8", "context": "C2 server"},
            {"type": "ip", "value": "45.155.205.33", "context": "Initial access IP"},
            {"type": "hash", "value": "a1b2c3d4e5f6789012345678abcdef01", "context": "Ransomware binary MD5"},
            {"type": "file", "value": "svchost32.exe", "context": "Masquerading process name"},
            {"type": "extension", "value": ".encrypted", "context": "Encrypted file extension"},
        ],
    },
    {
        "id": "INC-2026-0041",
        "title": "Brute Force Attack - Authentication Service",
        "severity": "SEV-2",
        "status": "investigating",
        "created": (datetime.utcnow() - timedelta(hours=2)).isoformat() + "Z",
        "services": ["auth-service", "api-gateway"],
        "commander": "soc-team@company.com",
        "timeline": [
            {"time": "-2h", "event": "Rate limit alerts on auth-service endpoints"},
            {"time": "-1h55m", "event": "843 failed SSH logins from 198.51.100.77 in 2 min"},
            {"time": "-1h50m", "event": "Distributed attack detected: 47 unique source IPs"},
            {"time": "-1h45m", "event": "Successful login detected from 198.51.100.77 using deploy-svc credentials"},
            {"time": "-1h40m", "event": "Incident declared SEV-2"},
        ],
        "iocs": [
            {"type": "ip", "value": "198.51.100.77", "context": "Primary attacker IP"},
            {"type": "ip", "value": "203.0.113.42", "context": "Secondary attacker IP"},
            {"type": "user", "value": "deploy-svc", "context": "Compromised service account"},
        ],
    },
]

DASHBOARDS = [
    {"id": "dash-sec-001", "title": "Security Operations Overview", "url": "https://app.datadoghq.com/dashboard/sec-001"},
    {"id": "dash-sec-002", "title": "Threat Detection & IOCs", "url": "https://app.datadoghq.com/dashboard/sec-002"},
    {"id": "dash-inf-001", "title": "Infrastructure Health", "url": "https://app.datadoghq.com/dashboard/inf-001"},
    {"id": "dash-net-001", "title": "Network Traffic Analysis", "url": "https://app.datadoghq.com/dashboard/net-001"},
]


def _ts(minutes_ago: int = 0) -> str:
    return (datetime.utcnow() - timedelta(minutes=minutes_ago)).isoformat() + "Z"


def _random_ts(max_minutes: int = 30) -> str:
    return _ts(random.randint(0, max_minutes))


# Security-focused log templates
LOG_TEMPLATES = [
    ("auth-service", "ERROR", "AuthHandler: Failed login attempt for user '{user}' from {ip} - invalid credentials (attempt {n}/5)"),
    ("auth-service", "CRITICAL", "AuthHandler: Account lockout triggered for user '{user}' - 5 consecutive failed attempts from {ip}"),
    ("auth-service", "WARN", "TokenValidator: Expired JWT presented by {ip}, user_id={user}"),
    ("auth-service", "ERROR", "LDAP: Connection refused to ldap://internal-auth:389, retry 3/3"),
    ("user-db", "CRITICAL", "Sysmon: Process 'svchost32.exe' (PID 4821) spawned by cmd.exe - SUSPICIOUS"),
    ("user-db", "CRITICAL", "FileMonitor: Mass rename detected - 847 files renamed to .encrypted in 60s"),
    ("user-db", "CRITICAL", "NetworkMonitor: Outbound TLS connection to 185.234.219.8:443 - NOT IN ALLOW LIST"),
    ("user-db", "ERROR", "BackupAgent: S3 DeleteObject failed - access denied (bucket policy changed?)"),
    ("user-db", "CRITICAL", "DiskMonitor: Write rate anomaly - 450MB/s sustained (normal: 20MB/s)"),
    ("api-gateway", "WARN", "RateLimiter: IP {ip} exceeded 1000 req/min threshold, throttling"),
    ("api-gateway", "ERROR", "WAF: SQL injection attempt blocked from {ip} on /api/v2/users?filter='"),
    ("api-gateway", "WARN", "TLS: Client {ip} using TLS 1.0 (deprecated) on /api/v2/payments"),
    ("payment-api", "ERROR", "PaymentProcessor: Timeout calling Stripe API after 5000ms, request_id=req-{n}"),
    ("payment-api", "WARN", "FraudDetector: Suspicious transaction pattern from merchant_id=m-{n}"),
    ("inventory-service", "INFO", "HealthCheck: All systems nominal, latency=23ms"),
    ("cdn-edge", "WARN", "GeoBlock: Request from sanctioned country blocked, ip={ip}"),
    ("notification-service", "ERROR", "SMTPRelay: Connection to smtp.internal:587 timed out"),
]

ATTACKER_IPS = [
    "185.234.219.8", "45.155.205.33", "198.51.100.77", "203.0.113.42",
    "91.243.44.128", "45.95.168.220", "185.220.101.15", "162.247.74.27",
]
NORMAL_IPS = ["10.0.1.50", "10.0.2.30", "172.16.0.100", "192.168.1.10"]
USERS = ["deploy-svc", "admin", "root", "ci-bot", "backup-admin", "jsmith", "analyst-01"]


@mcp.tool
def get_monitors(service: Optional[str] = None, status: Optional[str] = None, tag: Optional[str] = None) -> str:
    """Retrieve Datadog monitors with optional filtering by service, status, or tag.

    Args:
        service: Filter monitors by service name (e.g., 'auth-service', 'user-db')
        status: Filter by monitor status: 'Alert', 'Warn', 'OK', or 'No Data'
        tag: Filter by tag (e.g., 'security', 'ransomware', 'brute-force')
    """
    results = MONITORS[:]
    if service:
        results = [m for m in results if m.get("service", "").lower() == service.lower()]
    if status:
        results = [m for m in results if m["status"].lower() == status.lower()]
    if tag:
        results = [m for m in results if tag.lower() in [t.lower() for t in m.get("tags", [])]]
    return json.dumps({"monitors": results, "total": len(results)}, indent=2)


@mcp.tool
def get_monitor(monitor_id: int) -> str:
    """Get full details for a specific Datadog monitor by its numeric ID.

    Args:
        monitor_id: The numeric monitor ID (e.g., 1001)
    """
    for m in MONITORS:
        if m["id"] == monitor_id:
            return json.dumps(
                {**m, "notifications": ["#slack-soc-alerts", "@pagerduty-soc"], "last_triggered": _ts(5)},
                indent=2,
            )
    return json.dumps({"error": f"Monitor {monitor_id} not found"})


@mcp.tool
def search_logs(
    query: str, service: Optional[str] = None, level: Optional[str] = None, minutes_back: int = 30
) -> str:
    """Search Datadog logs with query filtering. Returns matching log entries.

    Args:
        query: Text search query (e.g., 'ransomware', 'failed login', 'svchost32')
        service: Restrict to a specific service (e.g., 'user-db')
        level: Log level filter: 'CRITICAL', 'ERROR', 'WARN', 'INFO'
        minutes_back: How many minutes of history to search (default 30)
    """
    logs = []
    for svc, lvl, tpl in LOG_TEMPLATES:
        if service and svc.lower() != service.lower():
            continue
        if level and lvl.upper() != level.upper():
            continue
        msg = tpl.format(
            ip=random.choice(ATTACKER_IPS + NORMAL_IPS),
            user=random.choice(USERS),
            n=random.randint(1000, 9999),
        )
        if query != "*" and query.lower() not in msg.lower() and query.lower() not in svc.lower():
            continue
        logs.append(
            {
                "timestamp": _random_ts(minutes_back),
                "service": svc,
                "level": lvl,
                "message": msg,
                "host": random.choice(HOSTS),
                "trace_id": f"trace-{random.randint(100000, 999999)}",
            }
        )
    logs.sort(key=lambda x: x["timestamp"], reverse=True)
    return json.dumps({"logs": logs, "total": len(logs), "query": query, "timeframe": f"last {minutes_back}m"}, indent=2)


@mcp.tool
def aggregate_logs(group_by: str = "service", level: Optional[str] = None) -> str:
    """Aggregate log counts grouped by a dimension. Useful for spotting anomalies.

    Args:
        group_by: Dimension to group by: 'service', 'level', or 'host'
        level: Optional level filter before aggregating (e.g., 'ERROR')
    """
    agg = {
        "service": {
            "auth-service": {"total": 4521, "error": 892, "critical": 23, "warn": 156},
            "user-db": {"total": 1203, "error": 67, "critical": 48, "warn": 34},
            "api-gateway": {"total": 12840, "error": 134, "critical": 2, "warn": 567},
            "payment-api": {"total": 3422, "error": 89, "critical": 0, "warn": 45},
            "inventory-service": {"total": 890, "error": 12, "critical": 0, "warn": 8},
            "cdn-edge": {"total": 5670, "error": 3, "critical": 0, "warn": 78},
            "notification-service": {"total": 445, "error": 34, "critical": 0, "warn": 12},
        },
        "level": {
            "CRITICAL": {"count": 73},
            "ERROR": {"count": 1231},
            "WARN": {"count": 900},
            "INFO": {"count": 27787},
        },
        "host": {
            "prod-db-01": {"total": 892, "error": 67, "critical": 48},
            "prod-db-02": {"total": 311, "error": 0, "critical": 0},
            "prod-web-01": {"total": 4521, "error": 134, "critical": 2},
            "prod-web-02": {"total": 4320, "error": 122, "critical": 0},
            "prod-api-01": {"total": 8540, "error": 89, "critical": 0},
            "prod-api-02": {"total": 8300, "error": 78, "critical": 0},
        },
    }
    data = agg.get(group_by, {})
    return json.dumps({"aggregation": data, "group_by": group_by, "timeframe": "last 30m"}, indent=2)


@mcp.tool
def get_metrics(metric_name: str, service: Optional[str] = None, minutes_back: int = 30) -> str:
    """Query a specific Datadog metric and get timeseries data points.

    Args:
        metric_name: The metric to query (e.g., 'system.cpu.user', 'auth.login.failed')
        service: Filter by service tag
        minutes_back: Time window in minutes (default 30)
    """
    defaults = {
        "system.cpu.user": (45.0, 15.0),
        "system.mem.pct_usable": (0.35, 0.1),
        "system.disk.in_use": (0.72, 0.05),
        "auth.login.failed": (120.0, 80.0),
        "auth.login.success": (450.0, 50.0),
        "trace.request.duration.p99": (0.8, 0.4),
        "trace.request.errors": (0.02, 0.03),
        "aws.s3.bytes_downloaded": (500000.0, 2000000.0),
        "network.bytes_sent": (1000000.0, 500000.0),
        "network.bytes_recv": (2000000.0, 800000.0),
    }
    base, var = defaults.get(metric_name, (100.0, 20.0))
    now = datetime.utcnow()
    points = [
        {
            "timestamp": (now - timedelta(minutes=minutes_back - i * (minutes_back // 12))).isoformat() + "Z",
            "value": round(max(0, base + random.gauss(0, var)), 4),
        }
        for i in range(12)
    ]
    return json.dumps(
        {"metric": metric_name, "service": service or "all", "points": points, "timeframe": f"last {minutes_back}m"},
        indent=2,
    )


@mcp.tool
def get_incidents(status: Optional[str] = None, severity: Optional[str] = None) -> str:
    """List security incidents with optional filtering.

    Args:
        status: Filter by 'active', 'investigating', 'resolved', or 'postmortem'
        severity: Filter by 'SEV-1', 'SEV-2', 'SEV-3'
    """
    results = INCIDENTS[:]
    if status:
        results = [i for i in results if i["status"].lower() == status.lower()]
    if severity:
        results = [i for i in results if i["severity"].upper() == severity.upper()]
    return json.dumps({"incidents": results, "total": len(results)}, indent=2)


@mcp.tool
def get_incident(incident_id: str) -> str:
    """Get full details for a specific incident including timeline and IOCs.

    Args:
        incident_id: The incident ID (e.g., 'INC-2026-0042')
    """
    for inc in INCIDENTS:
        if inc["id"] == incident_id:
            return json.dumps(inc, indent=2)
    return json.dumps({"error": f"Incident {incident_id} not found"})


@mcp.tool
def get_dashboards() -> str:
    """List all available Datadog dashboards."""
    return json.dumps({"dashboards": DASHBOARDS, "total": len(DASHBOARDS)}, indent=2)


@mcp.tool
def get_events(query: Optional[str] = None, hours_back: int = 24) -> str:
    """Search Datadog events (deployments, scaling, security alerts) within a timeframe.

    Args:
        query: Text filter for event titles/tags
        hours_back: Look back window in hours (default 24)
    """
    now = datetime.utcnow()
    events = [
        {
            "id": "evt-001",
            "title": "Deploy: user-db v3.2.1 to prod",
            "type": "deploy",
            "service": "user-db",
            "timestamp": (now - timedelta(hours=3)).isoformat() + "Z",
            "tags": ["deploy", "prod", "user-db"],
        },
        {
            "id": "evt-002",
            "title": "GuardDuty: UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration",
            "type": "security",
            "service": "auth-service",
            "timestamp": (now - timedelta(hours=1)).isoformat() + "Z",
            "tags": ["security", "guardduty", "iam"],
        },
        {
            "id": "evt-003",
            "title": "Auto-scaling: api-gateway scaled 4 -> 8 instances",
            "type": "scaling",
            "service": "api-gateway",
            "timestamp": (now - timedelta(hours=2)).isoformat() + "Z",
            "tags": ["scaling", "prod", "api-gateway"],
        },
        {
            "id": "evt-004",
            "title": "Security: New IAM user 'backup-admin' created by 'deploy-svc'",
            "type": "security",
            "service": "auth-service",
            "timestamp": (now - timedelta(minutes=50)).isoformat() + "Z",
            "tags": ["security", "iam", "suspicious"],
        },
        {
            "id": "evt-005",
            "title": "Security: S3 bucket policy modified on prod-backups",
            "type": "security",
            "service": "user-db",
            "timestamp": (now - timedelta(minutes=40)).isoformat() + "Z",
            "tags": ["security", "s3", "backup"],
        },
    ]
    if query:
        q = query.lower()
        events = [e for e in events if q in e["title"].lower() or any(q in t for t in e["tags"])]
    return json.dumps({"events": events, "total": len(events)}, indent=2)


@mcp.tool
def list_slos(service: Optional[str] = None) -> str:
    """Retrieve Service Level Objectives and their current burn rates.

    Args:
        service: Filter SLOs by associated service name
    """
    slos = [
        {
            "id": "slo-001",
            "name": "Auth Service Availability",
            "service": "auth-service",
            "target": 99.95,
            "current": 98.2,
            "status": "breaching",
            "burn_rate_1h": 8.5,
            "burn_rate_6h": 4.2,
        },
        {
            "id": "slo-002",
            "name": "Payment API P99 Latency < 500ms",
            "service": "payment-api",
            "target": 99.0,
            "current": 99.4,
            "status": "ok",
            "burn_rate_1h": 0.3,
            "burn_rate_6h": 0.2,
        },
        {
            "id": "slo-003",
            "name": "Database Query Success Rate",
            "service": "user-db",
            "target": 99.99,
            "current": 97.1,
            "status": "breaching",
            "burn_rate_1h": 12.8,
            "burn_rate_6h": 6.1,
        },
    ]
    if service:
        slos = [s for s in slos if s["service"].lower() == service.lower()]
    return json.dumps({"slos": slos, "total": len(slos)}, indent=2)


if __name__ == "__main__":
    mcp.run()
