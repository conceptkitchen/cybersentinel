"""Brute Force Attack Scenario.

Simulates a distributed brute force attack against SSH and API endpoints.
Severity: MEDIUM - activates Detection and Prevention agents.

Attack chain:
1. Distributed SSH brute force from 47 unique IPs
2. API endpoint credential stuffing
3. Rate limit exhaustion attempts
4. No successful compromise detected (yet)
"""

SCENARIO_NAME = "brute_force"
SCENARIO_SEVERITY = "MEDIUM"
SCENARIO_DESCRIPTION = "Distributed brute force attack on SSH and API endpoints"

ALERT = """MEDIUM SECURITY ALERT - Distributed Brute Force Attack

Timestamp: {timestamp}
Source: GuardDuty + WAF + Auth Service Logs

Timeline of events:
- T-30m: GuardDuty Recon:EC2/PortProbeUnprotectedPort - port 22 scan from multiple IPs
- T-25m: SSH failed login rate spiked to 843 attempts/min on prod-db-01
  47 unique source IPs detected (distributed attack)
- T-20m: WAF rate limit triggered on /api/v2/auth/login (1000+ req/min)
  Credential stuffing pattern: sequential usernames with common passwords
- T-15m: Auth service account lockouts triggered for: admin, root, deploy-svc, ci-bot
- T-10m: Port scanning detected on prod-web-01 and prod-api-01 (ports 22, 80, 443, 3306, 5432)
- T-5m: Attack ongoing, no successful authentication detected

Top Attacking IPs (by volume):
- 198.51.100.77 (China) - 2,341 attempts
- 203.0.113.42 (South Korea) - 1,892 attempts
- 91.243.44.128 (Ukraine) - 1,567 attempts
- 45.95.168.220 (Germany/Tor exit) - 1,234 attempts
- 185.220.101.15 (Netherlands) - 987 attempts

Targeted Services:
- SSH (port 22) on prod-db-01, prod-web-01
- /api/v2/auth/login on api-gateway
- /api/v2/admin/users on api-gateway

NOTE: No successful breach detected. Account lockouts are working.
However, the volume and distribution suggest a coordinated attack.
Preventive measures recommended: IP blocking, rate limiting hardening,
and monitoring for any successful login from these IP ranges.
"""


def get_alert(timestamp: str = None) -> str:
    """Get the formatted alert text."""
    from datetime import datetime
    if timestamp is None:
        timestamp = datetime.utcnow().isoformat() + "Z"
    return ALERT.format(timestamp=timestamp)
