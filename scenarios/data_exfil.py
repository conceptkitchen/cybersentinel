"""Data Exfiltration Scenario.

Simulates data exfiltration via compromised IAM credentials.
Severity: HIGH - activates Detection, Prevention, Response agents.

Attack chain:
1. Stolen EC2 instance credentials used from external IP
2. AssumeRole to cross-account admin role
3. S3 ListBuckets across all accounts
4. Bulk download of customer data bucket
5. Data staged to attacker-controlled S3 bucket
"""

SCENARIO_NAME = "data_exfil"
SCENARIO_SEVERITY = "HIGH"
SCENARIO_DESCRIPTION = "Data exfiltration via compromised IAM credentials"

ALERT = """HIGH SECURITY ALERT - Data Exfiltration in Progress

Timestamp: {timestamp}
Source: GuardDuty + CloudTrail + VPC Flow Logs

Timeline of events:
- T-2h: GuardDuty alert - IAM credentials from EC2 instance i-0abc123def456
  being used from IP 45.155.205.33 (OUTSIDE AWS, Netherlands)
- T-1h55m: AssumeRole to OrganizationAccountAccessRole (cross-account admin)
  Source: 45.155.205.33, User-Agent: aws-cli/2.15.0
- T-1h50m: S3 ListBuckets called across 3 AWS accounts (reconnaissance)
- T-1h45m: S3 GetObject burst began on s3://prod-customer-data
  Rate: 500 objects/min, estimated 47GB total
- T-1h20m: VPC Flow Logs show 47GB outbound to 45.155.205.33
- T-1h: S3 PutObject detected on external bucket (data staging)
- T-45m: Second round of exfiltration targeting s3://prod-financial-records

Affected Resources:
- IAM Role: deploy-svc-role (credentials exfiltrated from EC2)
- S3: prod-customer-data (47GB downloaded)
- S3: prod-financial-records (download in progress)
- Data: Customer PII, financial records, transaction history

Active IOCs:
- 45.155.205.33 (data exfiltration endpoint, Netherlands)
- deploy-svc-role (compromised IAM role)
- OrganizationAccountAccessRole (escalated to cross-account)

NOTE: No destructive actions detected yet. This appears to be
a data theft operation, not ransomware. Containment should focus
on credential revocation and network egress blocking.
"""


def get_alert(timestamp: str = None) -> str:
    """Get the formatted alert text."""
    from datetime import datetime
    if timestamp is None:
        timestamp = datetime.utcnow().isoformat() + "Z"
    return ALERT.format(timestamp=timestamp)
