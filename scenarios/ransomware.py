"""Ransomware Attack Scenario.

Simulates a ransomware attack on a production database server.
Severity: CRITICAL - activates all 4 agents.

Attack chain:
1. Brute force SSH credentials for deploy-svc account
2. Download ransomware payload from C2 server
3. Execute encryption of database files
4. Delete S3 backups to prevent recovery
5. Establish persistent C2 communication
"""

SCENARIO_NAME = "ransomware"
SCENARIO_SEVERITY = "CRITICAL"
SCENARIO_DESCRIPTION = "Active ransomware attack on production database server"

ALERT = """CRITICAL SECURITY ALERT - Multiple Indicators of Active Ransomware Attack

Timestamp: {timestamp}
Source: GuardDuty + Sysmon + CloudTrail correlation

Timeline of events:
- T-55m: Successful SSH login to prod-db-01 from external IP 45.155.205.33 using 'deploy-svc' credentials
  (preceded by 843 failed attempts from 198.51.100.77 - brute force detected)
- T-50m: New IAM user 'backup-admin' created by 'deploy-svc' from IP 45.155.205.33
- T-48m: AdministratorAccess policy attached to 'backup-admin'
- T-42m: Unusual process 'svchost32.exe' (PID 4821) spawned via bash on prod-db-01
  Command: /tmp/.svchost32.exe --encrypt --ext .encrypted --threads 8
- T-40m: Mass file encryption detected - 847 files/min being renamed to .encrypted
  Affected: /var/lib/postgresql/data/, /home/deploy-svc/, /opt/app/data/
- T-38m: Outbound TLS connection established to 185.234.219.8:443 (known C2 infrastructure)
- T-38m: S3 bucket policy modified on prod-backups by 'backup-admin'
- T-35m: S3 DeleteObject burst - 3 daily backups deleted from prod-backups bucket
- T-30m: Ransom note dropped: /tmp/README_DECRYPT.txt
  Content: "YOUR FILES HAVE BEEN ENCRYPTED. Send 5 BTC to bc1q... Contact: decrypt@proton.me"

Affected Resources:
- EC2: i-0abc123def456 (prod-db-01) - PRIMARY TARGET
- EC2: i-0abc123def789 (prod-db-02) - AT RISK (same subnet)
- IAM: deploy-svc (compromised), backup-admin (attacker-created)
- S3: prod-backups (backups deleted)
- Data: 2.3M customer PII records in PostgreSQL database

Active IOCs:
- 185.234.219.8 (C2 server, Russia)
- 45.155.205.33 (initial access, Netherlands)
- 198.51.100.77 (brute force origin, China)
- svchost32.exe (MD5: a1b2c3d4e5f6789012345678abcdef01)
- .encrypted file extension
- deploy-svc, backup-admin (compromised/attacker accounts)

This is an ACTIVE INCIDENT. The ransomware process is still running.
Immediate containment required.
"""


def get_alert(timestamp: str = None) -> str:
    """Get the formatted alert text."""
    from datetime import datetime
    if timestamp is None:
        timestamp = datetime.utcnow().isoformat() + "Z"
    return ALERT.format(timestamp=timestamp)
