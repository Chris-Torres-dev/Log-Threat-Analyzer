# Architecture Overview

## Data Flow

```
[Log File]
    │
    ▼
engine/engine.cpp
  - Reads raw log lines
  - Uses strstr pattern matching + sliding window brute-force tracker
  - Scores threat severity (LOW / MEDIUM / HIGH / CRITICAL)
  - Outputs JSON to stdout
    │
    ▼ (JSON via subprocess pipe)
backend/bridge.py
  - Launches engine as subprocess
  - Reads and parses JSON output
  - Runs AI analysis on batched events via Anthropic API
  - Serves results over WebSocket
    │
    ├──────────────────────┐
    ▼                      ▼
backend/terminal.py    frontend/Dashboard.jsx
  CLI live view           React UI
  (rich table,            (live feed, AI results,
   color-coded)            settings panel)
```

## Threat Severity Levels

| Level    | Description                              |
|----------|------------------------------------------|
| LOW      | Minor anomaly, likely benign             |
| MEDIUM   | Suspicious pattern, worth investigating  |
| HIGH     | Strong indicator of malicious activity   |
| CRITICAL | Active attack or confirmed breach signal |

## File Responsibilities

| File | Language | Responsibility |
|---|---|---|
| `engine/engine.cpp` | C++ | Fast log parsing, strstr detection, radix sort, hash table scoring |
| `backend/bridge.py` | Python | WebSocket server, AI batching, Anthropic API calls |
| `backend/terminal.py` | Python | Live terminal view with rich color-coded table |
| `frontend/Dashboard.jsx` | React | Real-time dashboard, AI results, settings |
