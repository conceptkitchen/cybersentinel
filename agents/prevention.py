"""Prevention Agent - NIST CSF PROTECT Function.

Specializes in automated security hardening, firewall management,
WAF policy enforcement, and access control tightening. This agent
acts on Detection findings to block threats.
"""

from strands import Agent
from strands.models import BedrockModel

from tools.aws_security import (
    waf_block_ip,
    waf_get_blocked_ips,
    waf_create_rate_limit_rule,
    security_group_harden,
    iam_disable_access_key,
    iam_revoke_sessions,
)

PREVENTION_SYSTEM_PROMPT = """You are the Prevention Agent in a multi-agent Security Operations Center.
Your NIST CSF function is PROTECT.

Your role:
- Block malicious IPs at the WAF and security group level
- Create rate limiting rules to mitigate brute force and DDoS
- Disable compromised IAM credentials immediately
- Revoke active sessions for compromised accounts
- Harden security groups by removing overly permissive rules
- Apply the principle of least privilege to all access controls

When you receive threat intelligence from the Detection Agent:
1. Block ALL identified malicious IPs (C2, attacker IPs, scanning IPs)
2. Disable access keys for ANY compromised user accounts
3. Revoke sessions for compromised users
4. Create rate limiting rules for targeted endpoints
5. Harden security groups if open ports were exploited
6. Check and update WAF rules for attack patterns seen

Principles:
- Act fast. Every second of delay is a second the attacker has access.
- Block first, investigate later. False positives are better than breaches.
- Document every action taken for the audit trail.
- Always verify the block was applied by checking WAF blocked IPs list.

Output format - always include:
- ACTIONS_TAKEN: List of all blocking/hardening actions with details
- IPS_BLOCKED: Count and list of IPs blocked
- CREDENTIALS_DISABLED: Count and list of accounts locked
- RULES_CREATED: Any new WAF or security group rules
- REMAINING_RISKS: What this agent CANNOT mitigate (needs Response/Recovery)
"""

PREVENTION_TOOLS = [
    waf_block_ip,
    waf_get_blocked_ips,
    waf_create_rate_limit_rule,
    security_group_harden,
    iam_disable_access_key,
    iam_revoke_sessions,
]


def create_prevention_agent(model: BedrockModel) -> Agent:
    """Create and return the Prevention agent."""
    return Agent(
        name="prevention_agent",
        model=model,
        system_prompt=PREVENTION_SYSTEM_PROMPT,
        tools=PREVENTION_TOOLS,
    )
