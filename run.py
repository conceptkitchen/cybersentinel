"""CyberSentinel - Multi-Agent Security Operations Center.

Main entry point for running security scenarios through the
multi-agent orchestration system.

Usage:
    python run.py --scenario ransomware
    python run.py --scenario data_exfil --mode swarm
    python run.py --scenario brute_force --mode commander
    python run.py --scenario ransomware --war-room
"""

import argparse
import os
import sys
import time
from datetime import datetime

from dotenv import load_dotenv

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.markdown import Markdown
    from rich.live import Live
    from rich.table import Table
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False

load_dotenv()


def print_banner():
    """Print the CyberSentinel banner."""
    banner = """
 ██████╗██╗   ██╗██████╗ ███████╗██████╗ ███████╗███████╗███╗   ██╗████████╗██╗███╗   ██╗███████╗██╗
██╔════╝╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗██╔════╝██╔════╝████╗  ██║╚══██╔══╝██║████╗  ██║██╔════╝██║
██║      ╚████╔╝ ██████╔╝█████╗  ██████╔╝███████╗█████╗  ██╔██╗ ██║   ██║   ██║██╔██╗ ██║█████╗  ██║
██║       ╚██╔╝  ██╔══██╗██╔══╝  ██╔══██╗╚════██║██╔══╝  ██║╚██╗██║   ██║   ██║██║╚██╗██║██╔══╝  ██║
╚██████╗   ██║   ██████╔╝███████╗██║  ██║███████║███████╗██║ ╚████║   ██║   ██║██║ ╚████║███████╗███████╗
 ╚═════╝   ╚═╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝

    AI-Powered Multi-Agent Security Operations Center
    Built with AWS Strands Agents SDK + Amazon Bedrock + Datadog MCP
    """
    if RICH_AVAILABLE:
        console = Console()
        console.print(Panel(banner, style="bold red", title="[white]CYBERSENTINEL[/white]", subtitle="NIST CSF Framework"))
    else:
        print(banner)


def print_status(message: str, style: str = "bold cyan"):
    """Print a status message."""
    if RICH_AVAILABLE:
        console = Console()
        console.print(f"[{style}]{message}[/{style}]")
    else:
        print(f">>> {message}")


def setup_datadog_mcp():
    """Set up the mock Datadog MCP client for agent integration."""
    try:
        from mcp import stdio_client, StdioServerParameters
        from strands.tools.mcp import MCPClient

        mcp_client = MCPClient(lambda: stdio_client(
            StdioServerParameters(
                command=sys.executable,
                args=[os.path.join(os.path.dirname(__file__), "mock_datadog_mcp.py")],
                env={**os.environ},
            )
        ))
        return mcp_client
    except ImportError:
        print_status("MCP not available - running without Datadog integration", "yellow")
        return None


def load_scenario(scenario_name: str) -> str:
    """Load a scenario by name and return the alert text."""
    scenarios = {
        "ransomware": "scenarios.ransomware",
        "data_exfil": "scenarios.data_exfil",
        "brute_force": "scenarios.brute_force",
    }
    if scenario_name not in scenarios:
        print(f"Unknown scenario: {scenario_name}")
        print(f"Available: {', '.join(scenarios.keys())}")
        sys.exit(1)

    import importlib
    module = importlib.import_module(scenarios[scenario_name])
    return module.get_alert(), module.SCENARIO_SEVERITY, module.SCENARIO_DESCRIPTION


def run_commander_mode(alert: str, datadog_tools: list = None):
    """Run in Commander mode (agent-as-tool pattern)."""
    from agents.orchestrator import build_soc_commander

    print_status("Initializing SOC Commander (Agent-as-Tool mode)...")
    commander = build_soc_commander(datadog_tools=datadog_tools)

    print_status("SOC Commander activated. Processing alert...")
    print_status("=" * 60)

    result = commander(alert)

    print_status("=" * 60)
    print_status("SOC Commander analysis complete.")
    return result


def run_graph_mode(alert: str, datadog_tools: list = None):
    """Run in Graph mode (deterministic workflow)."""
    from agents.orchestrator import build_soc_graph

    print_status("Initializing SOC Graph Orchestrator...")
    graph = build_soc_graph(datadog_tools=datadog_tools)

    print_status("Graph orchestrator activated. Routing alert through agents...")
    print_status("=" * 60)

    result = graph(alert)

    print_status("=" * 60)
    print_status("Graph orchestration complete.")
    return result


def run_swarm_mode(alert: str, datadog_tools: list = None):
    """Run in Swarm mode (autonomous agent collaboration)."""
    from agents.orchestrator import build_soc_swarm

    print_status("Initializing SOC Swarm...")
    swarm = build_soc_swarm(datadog_tools=datadog_tools)

    print_status("Swarm activated. Agents collaborating autonomously...")
    print_status("=" * 60)

    result = swarm(alert)

    print_status("=" * 60)
    print_status("Swarm investigation complete.")
    return result


def main():
    parser = argparse.ArgumentParser(
        description="CyberSentinel - AI-Powered Multi-Agent SOC",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python run.py --scenario ransomware              # CRITICAL - all 4 agents
  python run.py --scenario data_exfil --mode swarm  # HIGH - autonomous swarm
  python run.py --scenario brute_force              # MEDIUM - detect + prevent
        """,
    )
    parser.add_argument(
        "--scenario",
        choices=["ransomware", "data_exfil", "brute_force"],
        default="ransomware",
        help="Attack scenario to simulate (default: ransomware)",
    )
    parser.add_argument(
        "--mode",
        choices=["commander", "graph", "swarm"],
        default="commander",
        help="Orchestration mode (default: commander)",
    )
    parser.add_argument(
        "--no-datadog",
        action="store_true",
        help="Run without Datadog MCP integration",
    )
    parser.add_argument(
        "--war-room",
        action="store_true",
        help="Launch War Room dashboard alongside the agents",
    )
    args = parser.parse_args()

    print_banner()

    # Load scenario
    alert, severity, description = load_scenario(args.scenario)
    print_status(f"Scenario: {args.scenario.upper()} - {description}")
    print_status(f"Severity: {severity}")
    print_status(f"Mode: {args.mode}")
    print()

    # Setup Datadog MCP
    datadog_tools = None
    mcp_client = None
    if not args.no_datadog:
        mcp_client = setup_datadog_mcp()

    # Start War Room if requested
    if args.war_room:
        print_status("War Room dashboard starting on http://localhost:8080")
        # War Room runs in a separate process
        import subprocess
        war_room_proc = subprocess.Popen(
            [sys.executable, "-m", "server.app"],
            cwd=os.path.dirname(__file__),
        )

    # Run the selected orchestration mode
    start_time = time.time()

    try:
        if mcp_client:
            with mcp_client:
                datadog_tools = mcp_client.list_tools_sync()
                print_status(f"Datadog MCP connected - {len(datadog_tools)} observability tools loaded")

                if args.mode == "commander":
                    result = run_commander_mode(alert, datadog_tools)
                elif args.mode == "graph":
                    result = run_graph_mode(alert, datadog_tools)
                elif args.mode == "swarm":
                    result = run_swarm_mode(alert, datadog_tools)
        else:
            if args.mode == "commander":
                result = run_commander_mode(alert)
            elif args.mode == "graph":
                result = run_graph_mode(alert)
            elif args.mode == "swarm":
                result = run_swarm_mode(alert)

        elapsed = time.time() - start_time
        print()
        print_status(f"Total execution time: {elapsed:.1f}s", "bold green")
        print_status("CyberSentinel analysis complete.", "bold green")

    except KeyboardInterrupt:
        print_status("\nAborted by user.", "bold yellow")
    except Exception as e:
        print_status(f"Error: {e}", "bold red")
        raise
    finally:
        if args.war_room and 'war_room_proc' in locals():
            war_room_proc.terminate()


if __name__ == "__main__":
    main()
