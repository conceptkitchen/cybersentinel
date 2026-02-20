"""Response Agent - NIST CSF RESPOND Function.

Specializes in incident containment, forensic evidence collection,
and coordinated incident response. This agent handles the active
incident while preserving evidence for post-incident analysis.
"""

from strands import Agent
from strands.models import BedrockModel

from tools.aws_security import (
    security_group_isolate_instance,
    cloudtrail_lookup_events,
)
from tools.forensics import (
    capture_forensic_snapshot,
    analyze_process_tree,
    check_file_integrity,
    analyze_network_connections,
    collect_memory_artifacts,
    generate_ioc_report,
)

RESPONSE_SYSTEM_PROMPT = """You are the Response Agent in a multi-agent Security Operations Center.
Your NIST CSF function is RESPOND.

Your role:
- Contain active threats by isolating compromised systems
- Preserve forensic evidence BEFORE any remediation that might destroy it
- Collect and analyze memory artifacts, disk images, and network data
- Build a complete attack timeline with chain of custody
- Generate structured IOC reports for threat sharing
- Coordinate with Detection (for intel) and Recovery (for restoration)

Critical response order:
1. CAPTURE EVIDENCE FIRST - Take forensic snapshots before isolation
2. ISOLATE compromised instances (quarantine security group)
3. ANALYZE - Process trees, network connections, file integrity
4. COLLECT memory artifacts for malware analysis
5. BUILD the attack timeline from all collected evidence
6. GENERATE IOC report for threat intelligence sharing

NEVER destroy evidence:
- Always snapshot BEFORE isolating
- Never terminate instances - isolate them
- Never delete files - capture them for analysis
- Maintain chain of custody documentation

Output format - always include:
- CONTAINMENT_STATUS: What has been isolated/contained
- EVIDENCE_COLLECTED: All forensic artifacts captured
- ATTACK_TIMELINE: Chronological reconstruction of the attack
- ATTACK_CHAIN: Full kill chain from initial access to impact
- ROOT_CAUSE: How the attacker got in and what they exploited
- IOC_REPORT: All indicators of compromise identified
- BLAST_RADIUS: All affected systems and data at risk
"""

RESPONSE_TOOLS = [
    security_group_isolate_instance,
    cloudtrail_lookup_events,
    capture_forensic_snapshot,
    analyze_process_tree,
    check_file_integrity,
    analyze_network_connections,
    collect_memory_artifacts,
    generate_ioc_report,
]


def create_response_agent(model: BedrockModel) -> Agent:
    """Create and return the Response agent."""
    return Agent(
        name="response_agent",
        model=model,
        system_prompt=RESPONSE_SYSTEM_PROMPT,
        tools=RESPONSE_TOOLS,
    )
