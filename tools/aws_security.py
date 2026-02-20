"""AWS Security Tools for CyberSentinel agents.

Stub implementations that simulate AWS GuardDuty, SecurityHub, WAF,
CloudTrail, and security group operations. In production, these would
call real AWS APIs via boto3.
"""

import json
import random
from datetime import datetime, timedelta
from strands import tool


# -- GuardDuty Tools --

@tool
def guardduty_get_findings(severity: str = "all", max_results: int = 10) -> str:
    """Retrieve AWS GuardDuty security findings.

    GuardDuty provides intelligent threat detection for AWS infrastructure.
    Returns findings sorted by severity.

    Args:
        severity: Filter by 'HIGH', 'MEDIUM', 'LOW', or 'all'
        max_results: Maximum findings to return (default 10)
    """
    findings = [
        {
            "id": "gd-001",
            "type": "UnauthorizedAccess:EC2/MaliciousIPCaller.Custom",
            "severity": 8.9,
            "severity_label": "HIGH",
            "title": "EC2 instance communicating with known malicious IP",
            "description": "EC2 instance i-0abc123def456 is communicating with IP 185.234.219.8 which is on a threat intelligence list.",
            "resource": "i-0abc123def456 (prod-db-01)",
            "region": "us-west-2",
            "first_seen": (datetime.utcnow() - timedelta(minutes=42)).isoformat() + "Z",
            "last_seen": (datetime.utcnow() - timedelta(minutes=2)).isoformat() + "Z",
            "count": 847,
            "action": {"type": "NETWORK_CONNECTION", "direction": "OUTBOUND", "remote_ip": "185.234.219.8", "remote_port": 443},
            "mitre_attack": ["TA0011 - Command and Control", "T1071 - Application Layer Protocol"],
        },
        {
            "id": "gd-002",
            "type": "Recon:EC2/PortProbeUnprotectedPort",
            "severity": 5.0,
            "severity_label": "MEDIUM",
            "title": "Unprotected port on EC2 instance is being probed",
            "description": "Port 22 on EC2 instance i-0abc123def456 is being probed from multiple IPs.",
            "resource": "i-0abc123def456 (prod-db-01)",
            "region": "us-west-2",
            "first_seen": (datetime.utcnow() - timedelta(hours=3)).isoformat() + "Z",
            "last_seen": (datetime.utcnow() - timedelta(minutes=30)).isoformat() + "Z",
            "count": 2341,
            "action": {"type": "PORT_PROBE", "port": 22, "probing_ips": ["198.51.100.77", "203.0.113.42", "91.243.44.128"]},
            "mitre_attack": ["TA0043 - Reconnaissance", "T1046 - Network Service Discovery"],
        },
        {
            "id": "gd-003",
            "type": "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS",
            "severity": 9.0,
            "severity_label": "HIGH",
            "title": "Credentials from EC2 instance being used outside AWS",
            "description": "IAM credentials associated with EC2 instance i-0abc123def456 are being used from IP 45.155.205.33 outside of AWS.",
            "resource": "arn:aws:iam::123456789012:role/deploy-svc-role",
            "region": "us-west-2",
            "first_seen": (datetime.utcnow() - timedelta(minutes=55)).isoformat() + "Z",
            "last_seen": (datetime.utcnow() - timedelta(minutes=10)).isoformat() + "Z",
            "count": 34,
            "action": {"type": "AWS_API_CALL", "api": "AssumeRole", "source_ip": "45.155.205.33"},
            "mitre_attack": ["TA0006 - Credential Access", "T1552 - Unsecured Credentials"],
        },
        {
            "id": "gd-004",
            "type": "Trojan:EC2/BlackholeTraffic",
            "severity": 8.0,
            "severity_label": "HIGH",
            "title": "EC2 instance attempting to communicate with blackholed IP",
            "description": "EC2 instance i-0abc123def456 is attempting to communicate with IP addresses that are known to be associated with botnet command and control.",
            "resource": "i-0abc123def456 (prod-db-01)",
            "region": "us-west-2",
            "first_seen": (datetime.utcnow() - timedelta(minutes=38)).isoformat() + "Z",
            "last_seen": (datetime.utcnow() - timedelta(minutes=5)).isoformat() + "Z",
            "count": 156,
            "action": {"type": "NETWORK_CONNECTION", "direction": "OUTBOUND", "remote_ip": "185.234.219.8"},
            "mitre_attack": ["TA0011 - Command and Control", "T1573 - Encrypted Channel"],
        },
    ]
    if severity != "all":
        findings = [f for f in findings if f["severity_label"].upper() == severity.upper()]
    return json.dumps({"findings": findings[:max_results], "total": len(findings)}, indent=2)


@tool
def guardduty_get_ip_reputation(ip_address: str) -> str:
    """Check threat intelligence reputation for an IP address using GuardDuty threat lists.

    Args:
        ip_address: IPv4 address to check (e.g., '185.234.219.8')
    """
    known_bad = {
        "185.234.219.8": {"threat_score": 95, "categories": ["c2-server", "ransomware"], "country": "RU", "asn": "AS44477", "reports": 2847},
        "45.155.205.33": {"threat_score": 88, "categories": ["brute-force", "credential-theft"], "country": "NL", "asn": "AS207656", "reports": 1523},
        "198.51.100.77": {"threat_score": 72, "categories": ["ssh-scanner", "brute-force"], "country": "CN", "asn": "AS4134", "reports": 891},
        "203.0.113.42": {"threat_score": 65, "categories": ["port-scanner", "web-scraper"], "country": "KR", "asn": "AS4766", "reports": 445},
        "91.243.44.128": {"threat_score": 81, "categories": ["botnet", "spam"], "country": "UA", "asn": "AS58271", "reports": 672},
        "45.95.168.220": {"threat_score": 77, "categories": ["tor-exit", "proxy"], "country": "DE", "asn": "AS51167", "reports": 334},
    }
    if ip_address in known_bad:
        info = known_bad[ip_address]
        return json.dumps(
            {"ip": ip_address, "malicious": True, **info, "source": "GuardDuty ThreatIntelSet + AbuseIPDB"},
            indent=2,
        )
    return json.dumps(
        {"ip": ip_address, "malicious": False, "threat_score": random.randint(0, 15), "categories": [], "source": "GuardDuty ThreatIntelSet"},
        indent=2,
    )


# -- SecurityHub Tools --

@tool
def securityhub_get_findings(severity: str = "CRITICAL") -> str:
    """Get AWS SecurityHub aggregated security findings across all AWS security services.

    Args:
        severity: Filter by 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'
    """
    findings = [
        {
            "id": "sh-001",
            "source": "GuardDuty",
            "title": "EC2 instance communicating with known C2 server",
            "severity": "CRITICAL",
            "compliance_status": "FAILED",
            "resource": "i-0abc123def456",
            "remediation": "Isolate instance immediately. Revoke associated IAM credentials. Capture forensic image.",
            "standards": ["NIST 800-53 SI-4", "CIS AWS 4.15"],
        },
        {
            "id": "sh-002",
            "source": "Inspector",
            "title": "CVE-2024-21413 - Critical RCE in database engine",
            "severity": "CRITICAL",
            "compliance_status": "FAILED",
            "resource": "i-0abc123def456",
            "remediation": "Patch database engine to version 15.6.2 or later.",
            "standards": ["NIST 800-53 SI-2", "PCI-DSS 6.2"],
        },
        {
            "id": "sh-003",
            "source": "IAM Access Analyzer",
            "title": "S3 bucket prod-backups has public access enabled",
            "severity": "HIGH",
            "compliance_status": "FAILED",
            "resource": "arn:aws:s3:::prod-backups",
            "remediation": "Remove public access. Enable S3 Block Public Access at account level.",
            "standards": ["NIST 800-53 AC-3", "CIS AWS 2.1.5"],
        },
        {
            "id": "sh-004",
            "source": "Config",
            "title": "Security group allows unrestricted SSH access (0.0.0.0/0)",
            "severity": "HIGH",
            "compliance_status": "FAILED",
            "resource": "sg-0deadbeef1234",
            "remediation": "Restrict SSH access to specific CIDR ranges. Use Session Manager instead.",
            "standards": ["NIST 800-53 AC-4", "CIS AWS 5.2"],
        },
    ]
    filtered = [f for f in findings if f["severity"].upper() == severity.upper()] if severity != "all" else findings
    return json.dumps({"findings": filtered, "total": len(filtered), "source": "SecurityHub"}, indent=2)


# -- WAF Tools --

@tool
def waf_block_ip(ip_address: str, reason: str) -> str:
    """Add an IP address to the AWS WAF block list to prevent further requests.

    Args:
        ip_address: The IP to block in CIDR notation (e.g., '185.234.219.8/32')
        reason: Human-readable reason for blocking, stored in audit log
    """
    if "/" not in ip_address:
        ip_address += "/32"
    rule_id = f"waf-rule-{random.randint(10000, 99999)}"
    print(f"[WAF ACTION] Blocking {ip_address}: {reason}")
    return json.dumps(
        {
            "action": "BLOCK",
            "ip": ip_address,
            "rule_id": rule_id,
            "reason": reason,
            "waf_acl": "production-web-acl",
            "effective_at": datetime.utcnow().isoformat() + "Z",
            "status": "ACTIVE",
        },
        indent=2,
    )


@tool
def waf_get_blocked_ips() -> str:
    """List all currently blocked IPs in the WAF IP set."""
    blocked = [
        {"ip": "185.234.219.8/32", "reason": "C2 communication", "blocked_at": (datetime.utcnow() - timedelta(minutes=25)).isoformat() + "Z"},
        {"ip": "45.155.205.33/32", "reason": "Credential theft", "blocked_at": (datetime.utcnow() - timedelta(minutes=20)).isoformat() + "Z"},
        {"ip": "91.243.44.128/32", "reason": "Botnet activity", "blocked_at": (datetime.utcnow() - timedelta(hours=1)).isoformat() + "Z"},
    ]
    return json.dumps({"blocked_ips": blocked, "total": len(blocked), "waf_acl": "production-web-acl"}, indent=2)


@tool
def waf_create_rate_limit_rule(uri_path: str, max_requests: int, window_seconds: int = 300) -> str:
    """Create a WAF rate limiting rule for a specific API endpoint.

    Args:
        uri_path: The URI path to protect (e.g., '/api/v2/auth/login')
        max_requests: Maximum allowed requests per IP in the time window
        window_seconds: Time window in seconds (default 300 = 5 minutes)
    """
    rule_id = f"rate-{random.randint(10000, 99999)}"
    return json.dumps(
        {
            "rule_id": rule_id,
            "type": "RATE_BASED",
            "uri": uri_path,
            "limit": max_requests,
            "window": window_seconds,
            "action": "BLOCK",
            "status": "ACTIVE",
        },
        indent=2,
    )


# -- CloudTrail Tools --

@tool
def cloudtrail_lookup_events(event_name: Optional[str] = None, username: Optional[str] = None, minutes_back: int = 60) -> str:
    """Search AWS CloudTrail audit logs for API activity.

    Args:
        event_name: Filter by API action (e.g., 'CreateUser', 'AssumeRole', 'DeleteObject')
        username: Filter by IAM username or role
        minutes_back: How far back to search (default 60 min)
    """
    now = datetime.utcnow()
    events = [
        {
            "event_time": (now - timedelta(minutes=55)).isoformat() + "Z",
            "event_name": "AssumeRole",
            "username": "deploy-svc",
            "source_ip": "45.155.205.33",
            "user_agent": "aws-cli/2.15.0 Python/3.11.6",
            "resource": "arn:aws:iam::123456789012:role/OrganizationAccountAccessRole",
            "error_code": None,
            "region": "us-west-2",
        },
        {
            "event_time": (now - timedelta(minutes=50)).isoformat() + "Z",
            "event_name": "CreateUser",
            "username": "deploy-svc",
            "source_ip": "45.155.205.33",
            "user_agent": "aws-cli/2.15.0 Python/3.11.6",
            "resource": "arn:aws:iam::123456789012:user/backup-admin",
            "error_code": None,
            "region": "us-west-2",
        },
        {
            "event_time": (now - timedelta(minutes=48)).isoformat() + "Z",
            "event_name": "AttachUserPolicy",
            "username": "deploy-svc",
            "source_ip": "45.155.205.33",
            "user_agent": "aws-cli/2.15.0 Python/3.11.6",
            "resource": "arn:aws:iam::aws:policy/AdministratorAccess",
            "error_code": None,
            "region": "us-west-2",
        },
        {
            "event_time": (now - timedelta(minutes=40)).isoformat() + "Z",
            "event_name": "PutBucketPolicy",
            "username": "backup-admin",
            "source_ip": "45.155.205.33",
            "user_agent": "aws-cli/2.15.0 Python/3.11.6",
            "resource": "arn:aws:s3:::prod-backups",
            "error_code": None,
            "region": "us-west-2",
        },
        {
            "event_time": (now - timedelta(minutes=38)).isoformat() + "Z",
            "event_name": "DeleteObject",
            "username": "backup-admin",
            "source_ip": "45.155.205.33",
            "user_agent": "aws-cli/2.15.0 Python/3.11.6",
            "resource": "arn:aws:s3:::prod-backups/db-backup-2026-02-19.sql.gz",
            "error_code": None,
            "region": "us-west-2",
        },
        {
            "event_time": (now - timedelta(minutes=35)).isoformat() + "Z",
            "event_name": "DeleteObject",
            "username": "backup-admin",
            "source_ip": "45.155.205.33",
            "user_agent": "aws-cli/2.15.0 Python/3.11.6",
            "resource": "arn:aws:s3:::prod-backups/db-backup-2026-02-18.sql.gz",
            "error_code": None,
            "region": "us-west-2",
        },
    ]
    if event_name:
        events = [e for e in events if e["event_name"].lower() == event_name.lower()]
    if username:
        events = [e for e in events if e["username"].lower() == username.lower()]
    return json.dumps({"events": events, "total": len(events), "timeframe": f"last {minutes_back}m"}, indent=2)


# -- Security Group Tools --

@tool
def security_group_isolate_instance(instance_id: str, reason: str) -> str:
    """Isolate an EC2 instance by replacing its security groups with a quarantine group that blocks all traffic.

    This is a critical containment action. The instance will lose all network connectivity.

    Args:
        instance_id: EC2 instance ID to isolate (e.g., 'i-0abc123def456')
        reason: Reason for isolation, logged for audit trail
    """
    quarantine_sg = f"sg-quarantine-{random.randint(10000, 99999)}"
    print(f"[CONTAINMENT] Isolating {instance_id}: {reason}")
    return json.dumps(
        {
            "action": "ISOLATE",
            "instance_id": instance_id,
            "previous_security_groups": ["sg-0deadbeef1234", "sg-0feedface5678"],
            "quarantine_security_group": quarantine_sg,
            "quarantine_rules": {"inbound": "DENY ALL", "outbound": "DENY ALL (except CloudWatch logs)"},
            "reason": reason,
            "executed_at": datetime.utcnow().isoformat() + "Z",
            "status": "ISOLATED",
            "rollback_command": f"aws ec2 modify-instance-attribute --instance-id {instance_id} --groups sg-0deadbeef1234 sg-0feedface5678",
        },
        indent=2,
    )


@tool
def security_group_harden(security_group_id: str, action: str, port: int, cidr: str) -> str:
    """Modify a security group rule to harden access controls.

    Args:
        security_group_id: The security group ID (e.g., 'sg-0deadbeef1234')
        action: 'revoke' to remove a rule, 'authorize' to add a rule
        port: Port number to modify
        cidr: CIDR range for the rule (e.g., '10.0.0.0/8' for internal only)
    """
    return json.dumps(
        {
            "action": action.upper(),
            "security_group": security_group_id,
            "port": port,
            "cidr": cidr,
            "protocol": "tcp",
            "status": "APPLIED",
            "executed_at": datetime.utcnow().isoformat() + "Z",
        },
        indent=2,
    )


# -- IAM Tools --

@tool
def iam_disable_access_key(username: str, reason: str) -> str:
    """Disable all access keys for an IAM user to prevent credential abuse.

    Args:
        username: IAM username whose keys should be disabled
        reason: Reason for disabling, logged for audit trail
    """
    key_id = f"AKIA{''.join(random.choices('ABCDEFGHIJKLMNOPQRSTUVWXYZ234567', k=16))}"
    print(f"[IAM ACTION] Disabling access keys for {username}: {reason}")
    return json.dumps(
        {
            "action": "DISABLE_ACCESS_KEYS",
            "username": username,
            "keys_disabled": [key_id],
            "reason": reason,
            "executed_at": datetime.utcnow().isoformat() + "Z",
            "status": "DISABLED",
        },
        indent=2,
    )


@tool
def iam_revoke_sessions(username: str, reason: str) -> str:
    """Revoke all active sessions for an IAM user by attaching an inline deny-all policy.

    Args:
        username: IAM username whose sessions should be revoked
        reason: Reason for revocation
    """
    print(f"[IAM ACTION] Revoking all sessions for {username}: {reason}")
    return json.dumps(
        {
            "action": "REVOKE_SESSIONS",
            "username": username,
            "policy_attached": "AWSRevokeOlderSessions",
            "effective_before": datetime.utcnow().isoformat() + "Z",
            "reason": reason,
            "status": "REVOKED",
        },
        indent=2,
    )

from typing import Optional
