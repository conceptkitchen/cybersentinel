"""Infrastructure Management Tools for CyberSentinel agents.

Provides backup verification, service restoration, DNS management,
and system health monitoring capabilities for the Recovery agent.
"""

import json
import random
from datetime import datetime, timedelta
from typing import Optional
from strands import tool


@tool
def verify_backups(resource_type: str = "all") -> str:
    """Verify integrity and availability of backup resources.

    Checks S3 backup buckets, RDS snapshots, and EBS snapshots
    to confirm recovery options are available.

    Args:
        resource_type: Filter by 'rds', 's3', 'ebs', or 'all'
    """
    backups = {
        "s3": {
            "bucket": "prod-backups",
            "status": "COMPROMISED",
            "details": "Recent backups deleted by attacker. Oldest surviving backup: 7 days old.",
            "surviving_backups": [
                {"key": "db-backup-2026-02-13.sql.gz", "size_gb": 12.3, "last_modified": "2026-02-13T03:00:00Z", "integrity": "VERIFIED"},
            ],
            "deleted_backups": [
                {"key": "db-backup-2026-02-19.sql.gz", "deleted_at": (datetime.utcnow() - timedelta(minutes=38)).isoformat() + "Z", "deleted_by": "backup-admin"},
                {"key": "db-backup-2026-02-18.sql.gz", "deleted_at": (datetime.utcnow() - timedelta(minutes=35)).isoformat() + "Z", "deleted_by": "backup-admin"},
                {"key": "db-backup-2026-02-17.sql.gz", "deleted_at": (datetime.utcnow() - timedelta(minutes=33)).isoformat() + "Z", "deleted_by": "backup-admin"},
            ],
            "versioning_enabled": True,
            "recovery_note": "S3 versioning is enabled. Deleted objects can be recovered from version history.",
        },
        "rds": {
            "instance": "prod-userdb-cluster",
            "status": "AVAILABLE",
            "automated_snapshots": [
                {"id": "rds:prod-userdb-2026-02-20-03-00", "created": "2026-02-20T03:00:00Z", "size_gb": 85.4, "status": "available", "encrypted": True},
                {"id": "rds:prod-userdb-2026-02-19-03-00", "created": "2026-02-19T03:00:00Z", "size_gb": 84.9, "status": "available", "encrypted": True},
            ],
            "point_in_time_recovery": {"earliest": "2026-02-15T03:00:00Z", "latest": (datetime.utcnow() - timedelta(minutes=5)).isoformat() + "Z"},
            "recovery_note": "RDS automated snapshots and PITR are intact. Attacker did not compromise RDS backups.",
        },
        "ebs": {
            "volumes": [
                {"volume_id": "vol-0aaa111", "instance": "prod-db-01", "size_gb": 200, "encrypted": True},
                {"volume_id": "vol-0bbb222", "instance": "prod-db-01", "size_gb": 500, "encrypted": True},
            ],
            "snapshots": [
                {"snapshot_id": "snap-auto-001", "volume": "vol-0aaa111", "created": "2026-02-20T00:00:00Z", "status": "completed", "integrity": "VERIFIED"},
                {"snapshot_id": "snap-auto-002", "volume": "vol-0bbb222", "created": "2026-02-20T00:00:00Z", "status": "completed", "integrity": "VERIFIED"},
            ],
            "recovery_note": "EBS snapshots are intact. Can restore clean volumes from midnight snapshot.",
        },
    }
    if resource_type != "all":
        backups = {resource_type: backups.get(resource_type, {"error": f"Unknown type: {resource_type}"})}
    return json.dumps(
        {
            "backup_verification": backups,
            "verified_at": datetime.utcnow().isoformat() + "Z",
            "overall_recovery_feasibility": "HIGH - Multiple recovery paths available despite S3 backup deletion.",
        },
        indent=2,
    )


@tool
def restore_from_snapshot(snapshot_id: str, target_instance: Optional[str] = None) -> str:
    """Initiate system restoration from a backup snapshot.

    Creates a new clean instance or volume from the specified snapshot.

    Args:
        snapshot_id: The RDS or EBS snapshot ID to restore from
        target_instance: Optional target instance name (generates new if omitted)
    """
    if target_instance is None:
        target_instance = f"prod-db-01-restored-{random.randint(1000, 9999)}"
    is_rds = snapshot_id.startswith("rds:")
    print(f"[RECOVERY] Restoring from {snapshot_id} -> {target_instance}")
    return json.dumps(
        {
            "action": "RESTORE",
            "source_snapshot": snapshot_id,
            "target": target_instance,
            "type": "RDS" if is_rds else "EBS",
            "status": "INITIATED",
            "estimated_time_minutes": random.randint(10, 30),
            "initiated_at": datetime.utcnow().isoformat() + "Z",
            "security_config": {
                "security_groups": ["sg-restored-clean"],
                "subnet": "subnet-private-01",
                "public_access": False,
                "encryption": True,
            },
            "post_restore_checklist": [
                "Verify data integrity after restore completes",
                "Run application health checks",
                "Update DNS/load balancer to point to new instance",
                "Monitor for 30 minutes before declaring recovered",
                "Keep old instance isolated for forensic analysis",
            ],
        },
        indent=2,
    )


@tool
def recover_s3_deleted_objects(bucket: str, prefix: str = "") -> str:
    """Recover deleted objects from an S3 bucket using version history.

    S3 versioning allows recovery of objects even after deletion.

    Args:
        bucket: S3 bucket name
        prefix: Optional key prefix to filter recovery scope
    """
    recovered = [
        {"key": "db-backup-2026-02-19.sql.gz", "version_id": f"v-{random.randint(100000, 999999)}", "size_gb": 12.8, "status": "RECOVERED"},
        {"key": "db-backup-2026-02-18.sql.gz", "version_id": f"v-{random.randint(100000, 999999)}", "size_gb": 12.6, "status": "RECOVERED"},
        {"key": "db-backup-2026-02-17.sql.gz", "version_id": f"v-{random.randint(100000, 999999)}", "size_gb": 12.4, "status": "RECOVERED"},
    ]
    return json.dumps(
        {
            "action": "RECOVER_DELETED_OBJECTS",
            "bucket": bucket,
            "objects_recovered": recovered,
            "total_recovered": len(recovered),
            "total_size_gb": sum(r["size_gb"] for r in recovered),
            "recovery_method": "S3 version history (versioning was enabled)",
            "note": "All deleted backups recovered. Recommend moving to a separate, attacker-inaccessible bucket.",
        },
        indent=2,
    )


@tool
def check_service_health(service: Optional[str] = None) -> str:
    """Check the health status of production services.

    Args:
        service: Specific service to check, or all if omitted
    """
    services = {
        "api-gateway": {"status": "DEGRADED", "uptime": "99.2%", "error_rate": "2.1%", "p99_latency_ms": 1240, "note": "Elevated latency due to upstream db issues"},
        "auth-service": {"status": "DEGRADED", "uptime": "98.1%", "error_rate": "4.3%", "p99_latency_ms": 890, "note": "Rate limiting active due to brute force"},
        "user-db": {"status": "CRITICAL", "uptime": "0%", "error_rate": "100%", "p99_latency_ms": None, "note": "ISOLATED - Ransomware containment"},
        "payment-api": {"status": "HEALTHY", "uptime": "99.97%", "error_rate": "0.03%", "p99_latency_ms": 234, "note": "Operating normally"},
        "inventory-service": {"status": "HEALTHY", "uptime": "99.99%", "error_rate": "0.01%", "p99_latency_ms": 45, "note": "Operating normally"},
        "cdn-edge": {"status": "HEALTHY", "uptime": "100%", "error_rate": "0%", "p99_latency_ms": 12, "note": "Operating normally"},
        "notification-service": {"status": "HEALTHY", "uptime": "99.9%", "error_rate": "0.1%", "p99_latency_ms": 67, "note": "Operating normally"},
    }
    if service:
        result = {service: services.get(service, {"error": f"Unknown service: {service}"})}
    else:
        result = services
    critical = [s for s, v in result.items() if v.get("status") == "CRITICAL"]
    degraded = [s for s, v in result.items() if v.get("status") == "DEGRADED"]
    return json.dumps(
        {
            "services": result,
            "summary": {"critical": critical, "degraded": degraded, "total_services": len(result)},
            "checked_at": datetime.utcnow().isoformat() + "Z",
        },
        indent=2,
    )


@tool
def update_dns_failover(service: str, target: str, ttl: int = 60) -> str:
    """Update DNS to point a service to a failover target.

    Args:
        service: Service name to update (e.g., 'user-db')
        target: New target endpoint (e.g., 'prod-db-01-restored-1234.internal')
        ttl: DNS TTL in seconds (default 60 for fast propagation)
    """
    return json.dumps(
        {
            "action": "DNS_FAILOVER",
            "service": service,
            "record": f"{service}.internal.company.com",
            "previous_target": "prod-db-01.internal.company.com",
            "new_target": target,
            "ttl": ttl,
            "status": "PROPAGATING",
            "estimated_propagation": f"{ttl} seconds",
            "executed_at": datetime.utcnow().isoformat() + "Z",
        },
        indent=2,
    )


@tool
def create_incident_report(
    incident_id: str,
    severity: str,
    title: str,
    executive_summary: str,
    technical_details: str,
    timeline: str,
    root_cause: str,
    containment_actions: str,
    recovery_actions: str,
    recommendations: str,
) -> str:
    """Create a comprehensive incident report for stakeholders and compliance.

    Args:
        incident_id: Incident tracking ID
        severity: SEV-1, SEV-2, or SEV-3
        title: Incident title
        executive_summary: Non-technical summary (2-3 sentences)
        technical_details: Technical analysis including IOCs and attack chain
        timeline: Chronological event timeline
        root_cause: Root cause analysis
        containment_actions: Actions taken to contain the threat
        recovery_actions: Actions taken or planned for recovery
        recommendations: Recommendations to prevent recurrence
    """
    report = {
        "incident_id": incident_id,
        "severity": severity,
        "title": title,
        "status": "DRAFT",
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "generated_by": "CyberSentinel AI SOC",
        "sections": {
            "executive_summary": executive_summary,
            "technical_details": technical_details,
            "timeline": timeline,
            "root_cause": root_cause,
            "containment_actions": containment_actions,
            "recovery_actions": recovery_actions,
            "recommendations": recommendations,
        },
        "compliance_notes": {
            "notification_required": severity in ["SEV-1", "SEV-2"],
            "frameworks": ["NIST CSF", "SOC 2", "PCI-DSS"],
            "data_breach": "Assessment pending - PII exposure analysis needed",
            "notification_deadline": "72 hours from discovery per GDPR, state laws vary",
        },
    }
    return json.dumps(report, indent=2)
