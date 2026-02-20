"""War Room Dashboard Server.

FastAPI backend that serves the War Room dashboard and provides
WebSocket connections for real-time agent activity updates.
"""

import asyncio
import json
import os
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.staticfiles import StaticFiles
import uvicorn

app = FastAPI(title="CyberSentinel War Room", version="1.0.0")

# Global state for connected War Room clients
connected_clients: list[WebSocket] = []
agent_status: dict = {
    "detection": {"status": "idle", "last_action": None, "findings": []},
    "prevention": {"status": "idle", "last_action": None, "actions": []},
    "response": {"status": "idle", "last_action": None, "evidence": []},
    "recovery": {"status": "idle", "last_action": None, "progress": []},
    "commander": {"status": "idle", "current_phase": None, "severity": None},
}
activity_log: list[dict] = []
current_incident: Optional[dict] = None


async def broadcast(message: dict):
    """Broadcast a message to all connected War Room clients."""
    disconnected = []
    for client in connected_clients:
        try:
            await client.send_json(message)
        except Exception:
            disconnected.append(client)
    for client in disconnected:
        connected_clients.remove(client)


def log_activity(agent: str, action: str, details: str = "", severity: str = "info"):
    """Log an agent activity and broadcast to War Room."""
    entry = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "agent": agent,
        "action": action,
        "details": details,
        "severity": severity,
    }
    activity_log.append(entry)
    # Keep last 100 entries
    if len(activity_log) > 100:
        activity_log.pop(0)
    # Async broadcast
    asyncio.create_task(broadcast({"type": "activity", "data": entry}))


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    """WebSocket endpoint for real-time War Room updates."""
    await websocket.accept()
    connected_clients.append(websocket)

    # Send current state on connect
    await websocket.send_json({
        "type": "init",
        "data": {
            "agent_status": agent_status,
            "activity_log": activity_log[-50:],
            "incident": current_incident,
        },
    })

    try:
        while True:
            data = await websocket.receive_text()
            msg = json.loads(data)
            if msg.get("type") == "ping":
                await websocket.send_json({"type": "pong"})
    except WebSocketDisconnect:
        connected_clients.remove(websocket)


@app.get("/api/status")
def get_status():
    """Get current agent statuses."""
    return {"agents": agent_status, "incident": current_incident}


@app.get("/api/activity")
def get_activity(limit: int = 50):
    """Get recent activity log."""
    return {"activity": activity_log[-limit:]}


@app.post("/api/scenario/{scenario_name}")
async def trigger_scenario(scenario_name: str, mode: str = "commander"):
    """Trigger a scenario from the War Room dashboard."""
    global current_incident
    current_incident = {
        "scenario": scenario_name,
        "mode": mode,
        "started_at": datetime.utcnow().isoformat() + "Z",
        "status": "active",
    }
    await broadcast({"type": "incident", "data": current_incident})
    log_activity("commander", "INCIDENT_DECLARED", f"Scenario: {scenario_name}, Mode: {mode}", "critical")
    return {"status": "triggered", "scenario": scenario_name}


@app.post("/api/agent/{agent_name}/update")
async def update_agent(agent_name: str, status: str, action: str = "", details: str = ""):
    """Update an agent's status (called by agents during execution)."""
    if agent_name in agent_status:
        agent_status[agent_name]["status"] = status
        agent_status[agent_name]["last_action"] = action
        await broadcast({"type": "agent_update", "data": {"agent": agent_name, "status": status, "action": action}})
        if action:
            severity = "critical" if status == "alert" else "warning" if status == "active" else "info"
            log_activity(agent_name, action, details, severity)
    return {"status": "updated"}


@app.get("/", response_class=HTMLResponse)
def serve_war_room():
    """Serve the War Room dashboard."""
    war_room_path = Path(__file__).parent.parent / "war-room" / "index.html"
    if war_room_path.exists():
        return war_room_path.read_text()
    return HTMLResponse("<h1>War Room - index.html not found</h1>", status_code=404)


if __name__ == "__main__":
    port = int(os.getenv("WAR_ROOM_PORT", "8080"))
    print(f"CyberSentinel War Room starting on http://localhost:{port}")
    uvicorn.run(app, host="0.0.0.0", port=port)
