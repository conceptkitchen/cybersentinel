"""SOC Commander - Multi-Agent Orchestrator.

Coordinates all 4 security agents using the Strands Graph pattern.
Routes alerts through Detection -> Prevention -> Response -> Recovery
with conditional branching based on threat severity.

Also supports a Swarm mode for real-time collaborative investigation.
"""

import os
import json
from typing import Optional

from strands import Agent, tool
from strands.models import BedrockModel
from strands.multiagent import GraphBuilder, Swarm
from strands.multiagent.graph import GraphState
from strands.multiagent.base import Status

from agents.detection import create_detection_agent, DETECTION_TOOLS
from agents.prevention import create_prevention_agent, PREVENTION_TOOLS
from agents.response import create_response_agent, RESPONSE_TOOLS
from agents.recovery import create_recovery_agent, RECOVERY_TOOLS


def get_bedrock_model(temperature: float = 0.2) -> BedrockModel:
    """Create a BedrockModel with configuration from environment."""
    model_id = os.getenv("BEDROCK_MODEL_ID", "us.anthropic.claude-sonnet-4-20250514-v1:0")
    region = os.getenv("AWS_REGION", "us-west-2")
    return BedrockModel(
        model_id=model_id,
        region_name=region,
        temperature=temperature,
        streaming=True,
    )


# ---- Severity-based conditional routing functions ----

def is_critical(state: GraphState) -> bool:
    """Route to full response pipeline for CRITICAL threats."""
    detect_result = state.results.get("detect")
    if not detect_result:
        return False
    text = str(detect_result.result).upper()
    return "CRITICAL" in text


def is_high(state: GraphState) -> bool:
    """Route to prevention + response for HIGH threats."""
    detect_result = state.results.get("detect")
    if not detect_result:
        return False
    text = str(detect_result.result).upper()
    return "HIGH" in text and "CRITICAL" not in text


def is_medium_or_low(state: GraphState) -> bool:
    """Route to prevention only for MEDIUM/LOW threats."""
    detect_result = state.results.get("detect")
    if not detect_result:
        return False
    text = str(detect_result.result).upper()
    return ("MEDIUM" in text or "LOW" in text) and "HIGH" not in text and "CRITICAL" not in text


def response_complete(state: GraphState) -> bool:
    """Check if containment/response phase is done."""
    respond = state.results.get("respond")
    prevent = state.results.get("prevent")
    return (
        (respond is not None and respond.status == Status.COMPLETED)
        or (prevent is not None and prevent.status == Status.COMPLETED)
    )


def always_true(state: GraphState) -> bool:
    """Always proceed (unconditional edge)."""
    return True


# ---- Graph-based Orchestrator ----

def build_soc_graph(
    model: Optional[BedrockModel] = None,
    datadog_tools: Optional[list] = None,
) -> object:
    """Build the SOC Commander graph orchestrator.

    The graph routes security alerts through agents based on severity:

    CRITICAL: Detect -> [Prevent + Respond (parallel)] -> Recover -> Report
    HIGH:     Detect -> [Prevent + Respond (parallel)] -> Report
    MEDIUM:   Detect -> Prevent -> Report
    LOW:      Detect -> Report

    Args:
        model: BedrockModel instance (creates default if None)
        datadog_tools: Optional list of Datadog MCP tools to add to Detection agent
    """
    if model is None:
        model = get_bedrock_model()

    # Create specialized agents
    detection = create_detection_agent(model)
    prevention = create_prevention_agent(model)
    response = create_response_agent(model)
    recovery = create_recovery_agent(model)

    # If Datadog MCP tools are provided, add them to the detection agent
    if datadog_tools:
        detection = Agent(
            name="detection_agent",
            model=model,
            system_prompt=detection.system_prompt,
            tools=DETECTION_TOOLS + datadog_tools,
        )

    # Executive report agent synthesizes all findings
    report_agent = Agent(
        name="executive_reporter",
        model=model,
        system_prompt="""You are the Executive Report Generator for the SOC Commander.

Synthesize ALL findings from the security agents into a comprehensive incident report.

Your report MUST include these sections:

## Executive Summary
2-3 sentences, non-technical. What happened, what's the impact, what did we do.

## Threat Classification
- Severity, type, confidence level
- MITRE ATT&CK mapping

## Attack Timeline
Chronological events from initial access to containment.

## Technical Analysis
- IOCs (IPs, hashes, domains, usernames)
- Attack chain / kill chain
- Root cause

## Actions Taken
- Detection actions
- Prevention actions (IPs blocked, credentials disabled)
- Response actions (isolation, evidence collection)
- Recovery actions (restoration, failover)

## Blast Radius
What systems and data were affected.

## Remediation Roadmap
- Immediate (0-24h)
- Short-term (1-7 days)
- Long-term (30-90 days)

## Lessons Learned
What should change to prevent recurrence.

Be factual, cite specific evidence, and make recommendations actionable.""",
    )

    # Build the orchestration graph
    builder = GraphBuilder()

    # Add all agent nodes
    builder.add_node(detection, "detect")
    builder.add_node(prevention, "prevent")
    builder.add_node(response, "respond")
    builder.add_node(recovery, "recover")
    builder.add_node(report_agent, "report")

    # Detection always runs first, then routes by severity:

    # CRITICAL path: Detect -> Prevent + Respond (parallel) -> Recover -> Report
    builder.add_edge("detect", "prevent", condition=is_critical)
    builder.add_edge("detect", "respond", condition=is_critical)
    builder.add_edge("respond", "recover", condition=response_complete)
    builder.add_edge("recover", "report")

    # HIGH path: Detect -> Prevent + Respond -> Report
    builder.add_edge("detect", "prevent", condition=is_high)
    builder.add_edge("detect", "respond", condition=is_high)
    builder.add_edge("prevent", "report", condition=response_complete)
    builder.add_edge("respond", "report", condition=response_complete)

    # MEDIUM path: Detect -> Prevent -> Report
    builder.add_edge("detect", "prevent", condition=is_medium_or_low)
    builder.add_edge("prevent", "report")

    # Safety limits
    builder.set_execution_timeout(900)  # 15 minutes max
    builder.set_max_node_executions(3)  # Prevent infinite loops

    return builder.build()


# ---- Swarm-based Orchestrator (alternative) ----

def build_soc_swarm(
    model: Optional[BedrockModel] = None,
    datadog_tools: Optional[list] = None,
) -> Swarm:
    """Build a Swarm-based SOC for collaborative real-time investigation.

    In Swarm mode, agents hand off to each other autonomously based on
    their findings. Better for complex, evolving incidents.

    Args:
        model: BedrockModel instance
        datadog_tools: Optional Datadog MCP tools for detection
    """
    if model is None:
        model = get_bedrock_model()

    detect_tools = DETECTION_TOOLS[:]
    if datadog_tools:
        detect_tools.extend(datadog_tools)

    # Swarm agents with handoff instructions
    threat_hunter = Agent(
        name="threat_hunter",
        model=model,
        system_prompt="""You are the Threat Hunter in a security operations swarm.

Your job: Detect and classify the threat using all available tools.

After your analysis:
- If CRITICAL threat (ransomware, active breach): handoff to containment_lead AND network_defender simultaneously
- If HIGH threat (confirmed malicious activity): handoff to network_defender
- If MEDIUM/LOW: handoff to recovery_coordinator directly

Available agents: network_defender, containment_lead, recovery_coordinator""",
        tools=detect_tools,
    )

    network_defender = Agent(
        name="network_defender",
        model=model,
        system_prompt="""You are the Network Defender in a security operations swarm.

Your job: Block threats at the network level using WAF, security groups, and IAM controls.

Actions:
1. Block ALL malicious IPs at WAF
2. Disable compromised credentials
3. Create rate limiting rules for attacked endpoints
4. Harden security groups

After containment:
- If instance isolation needed: handoff to containment_lead
- If threats blocked, need recovery: handoff to recovery_coordinator

Available agents: containment_lead, recovery_coordinator""",
        tools=PREVENTION_TOOLS,
    )

    containment_lead = Agent(
        name="containment_lead",
        model=model,
        system_prompt="""You are the Containment Lead in a security operations swarm.

Your job: Isolate compromised systems and collect forensic evidence.

Critical order:
1. SNAPSHOT first (preserve evidence)
2. ISOLATE the instance
3. ANALYZE (process tree, network, files, memory)
4. GENERATE IOC report

After containment and evidence collection:
- handoff to recovery_coordinator with full findings

Available agents: recovery_coordinator""",
        tools=RESPONSE_TOOLS,
    )

    recovery_coordinator = Agent(
        name="recovery_coordinator",
        model=model,
        system_prompt="""You are the Recovery Coordinator in a security operations swarm.

Your job: Restore services and create the final incident report.

Process:
1. Verify backup integrity
2. Recover deleted backups if needed
3. Restore from clean snapshots
4. DNS failover to restored instances
5. Monitor service health
6. Create comprehensive incident report

When recovery is complete, call complete_swarm_task with the full incident report.""",
        tools=RECOVERY_TOOLS,
    )

    return Swarm(
        agents=[threat_hunter, network_defender, containment_lead, recovery_coordinator],
        entry_point=threat_hunter,
        max_handoffs=20,
        max_iterations=15,
        execution_timeout=900.0,
        node_timeout=300.0,
        repetitive_handoff_detection_window=6,
    )


# ---- Simple Agent-as-Tool Orchestrator (lightweight demo) ----

def build_soc_commander(
    model: Optional[BedrockModel] = None,
    datadog_tools: Optional[list] = None,
) -> Agent:
    """Build a simple SOC Commander that delegates to specialist agents as tools.

    This is the most straightforward pattern - each specialist agent is wrapped
    as a callable tool for the commander to invoke.

    Best for demos where you want to show the commander's decision-making.
    """
    if model is None:
        model = get_bedrock_model()

    detect_agent = create_detection_agent(model)
    prevent_agent = create_prevention_agent(model)
    respond_agent = create_response_agent(model)
    recover_agent = create_recovery_agent(model)

    # Add Datadog tools to detection if available
    if datadog_tools:
        detect_agent = Agent(
            name="detection_agent",
            model=model,
            system_prompt=detect_agent.system_prompt,
            tools=DETECTION_TOOLS + datadog_tools,
        )

    @tool
    def run_detection(alert_details: str) -> str:
        """Activate the Detection Agent to analyze a security alert and identify threats.

        Use this FIRST for any security alert. The Detection Agent will identify IOCs,
        classify severity, and map to MITRE ATT&CK.

        Args:
            alert_details: Full description of the security alert to investigate
        """
        result = detect_agent(alert_details)
        return str(result)

    @tool
    def run_prevention(threat_intel: str) -> str:
        """Activate the Prevention Agent to block threats and harden defenses.

        Use after Detection has identified threats. Provide the Detection Agent's
        findings including malicious IPs, compromised accounts, and attack vectors.

        Args:
            threat_intel: Detection Agent's findings including IOCs and severity
        """
        result = prevent_agent(threat_intel)
        return str(result)

    @tool
    def run_response(incident_details: str) -> str:
        """Activate the Response Agent for incident containment and forensics.

        Use for CRITICAL and HIGH severity incidents. The Response Agent will
        isolate systems, collect evidence, and build the attack timeline.

        Args:
            incident_details: Full incident context including affected systems and IOCs
        """
        result = respond_agent(incident_details)
        return str(result)

    @tool
    def run_recovery(incident_summary: str) -> str:
        """Activate the Recovery Agent to restore systems and generate the final report.

        Use after containment is complete. The Recovery Agent verifies backups,
        restores services, and creates the incident report.

        Args:
            incident_summary: Summary of the incident, containment actions, and what needs restoration
        """
        result = recover_agent(incident_summary)
        return str(result)

    commander = Agent(
        name="soc_commander",
        model=model,
        system_prompt="""You are the SOC Commander - the lead incident coordinator for CyberSentinel.

You manage 4 specialized security agents across the NIST Cybersecurity Framework:

1. DETECTION AGENT (DETECT) - Threat hunting and IOC identification
2. PREVENTION AGENT (PROTECT) - Blocking threats and hardening defenses
3. RESPONSE AGENT (RESPOND) - Containment and forensics
4. RECOVERY AGENT (RECOVER) - System restoration and reporting

For every security alert, follow this protocol:

1. ALWAYS start with run_detection to classify the threat
2. Based on severity:
   - CRITICAL: Run prevention AND response in sequence, then recovery
   - HIGH: Run prevention, then response, then recovery
   - MEDIUM: Run prevention, then recovery for reporting only
   - LOW: Run prevention only, log and monitor
3. ALWAYS end with a commander's summary

Your summary must include:
- Incident severity and type
- Which agents were activated and what they found
- Current system status
- Top 3 immediate recommendations

You are calm, methodical, and thorough. Every second counts in an active incident.
Never skip an agent when severity warrants it. Better to over-respond than under-respond.
""",
        tools=[run_detection, run_prevention, run_response, run_recovery],
    )

    return commander
