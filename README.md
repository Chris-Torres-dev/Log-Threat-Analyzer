# Log Threat Analyzer (In progress)

A cybersecurity tool that analyzes system and network logs to detect suspicious activity, flag potential threats, and generate risk summaries with AI-powered response recommendations.

---

## Architecture

```
Log File Input
      │
      ▼
engine/engine.cpp        ← C++: strstr detection, radix sort, sliding window brute-force
      │
      │ JSON via stdout
      ▼
backend/bridge.py        ← Python: WebSocket server, AI batching, Anthropic API
      │
   ┌──┴──────────────┐
   ▼                 ▼
terminal.py       Dashboard.jsx
(CLI live view)   (React UI)
```

---

## Project Structure

```
Log-Threat-Analyzer/
├── engine/
│   └── engine.cpp          # C++ detection engine
├── backend/
│   ├── bridge.py           # Python/C++ bridge + WebSocket server
│   ├── terminal.py         # CLI live view
│   └── requirements.txt    # Python dependencies
├── frontend/
│   ├── Dashboard.jsx       # React dashboard
│   └── package.json
├── logs/
│   └── samples/            # Sample log files for testing
├── tests/
│   ├── test_bridge.py
│   └── test_terminal.py
├── docs/
│   └── ARCHITECTURE.md
├── .github/
│   └── ISSUE_TEMPLATE/
├── .env.example
├── .gitignore
├── CONTRIBUTING.md
├── LICENSE
├── Makefile
└── README.md
```

---

## Getting Started

### 1. Clone the repo
```bash
git clone https://github.com/Chris-Torres-dev/Log-Threat-Analyzer.git
cd Log-Threat-Analyzer
```

### 2. Build the C++ engine
```bash
make
```

### 3. Install Python dependencies
```bash
pip install -r backend/requirements.txt
```

### 4. Set up environment
```bash
cp .env.example .env
# Add your ANTHROPIC_API_KEY to .env
```

### 5. Run

**Demo mode (no log file needed):**
```bash
./engine/engine --demo | python3 backend/bridge.py --demo
```

**Live mode (tail a real log file):**
```bash
./engine/engine /var/log/auth.log | python3 backend/bridge.py
```

**Terminal view only:**
```bash
python3 backend/terminal.py --demo
```

---

## Branch Structure

| Branch | Purpose |
|---|---|
| `main` | Stable releases only |
| `dev` | Active development |
| `feature/engine-parser` | C++ parsing improvements |
| `feature/threat-detection` | Detection logic |
| `feature/dashboard-ui` | React frontend |
| `feature/terminal-cli` | CLI improvements |

---

## Features

- [x] C++ log parsing engine with strstr pattern detection
- [x] Sliding window brute-force tracker (FNV hash table)
- [x] Radix sort for event ordering
- [x] Threat scoring per IP (0–100)
- [x] JSON output pipeline to Python bridge
- [x] WebSocket server for real-time UI updates
- [x] AI analysis via Anthropic API (pattern detection across events)
- [x] React dashboard with live feed and settings
- [x] Rich terminal live view
- [ ] Export reports as JSON or PDF
- [ ] Config file support for engine thresholds
- [ ] Docker setup

---

## Running Tests

```bash
python3 -m pytest tests/
```

---

## Contributing

See [CONTRIBUTING.md](./CONTRIBUTING.md) for branching rules and commit conventions.

---

## License

MIT — see [LICENSE](./LICENSE)
