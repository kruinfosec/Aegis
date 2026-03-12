# Aegis — Smart Contract Vulnerability Scanner

> A lightweight security analysis tool by **Kru Infosec** — a mini Mythril for detecting common vulnerabilities in Ethereum smart contracts.

## Features

- 🔍 **6 Vulnerability Detectors** — Reentrancy, Integer Overflow, tx.origin Misuse, Unprotected Selfdestruct, Weak Randomness, Unchecked Call Returns
- 🌐 **Web UI** — Drag-and-drop Solidity file upload with a dark cyberpunk interface
- ⛓️ **Blockchain Simulation** — Ganache-based attack scenario demonstration (requires Node.js)
- 📄 **Detailed Reports** — Per-finding severity badges, code snippets, and fix suggestions
- ⚡ **Quick Test Samples** — 4 built-in contracts to test the scanner instantly

---

## Quick Start

### 1. Install Dependencies

```bash
pip install flask==3.0.3 werkzeug==3.0.3
# Optional (for blockchain simulation):
pip install web3
```

### 2. Run the App

```bash
python app.py
```

Open **http://127.0.0.1:5000** in your browser.

---

## Project Structure

```
Aegis/
├── app.py                      # Flask web app
├── requirements.txt
├── scanner/
│   ├── parser.py               # Solidity validation + pragma detection
│   ├── engine.py               # Orchestrates all detectors
│   ├── report.py               # Formats findings for templates
│   └── detectors/
│       ├── reentrancy.py       # Reentrancy attack detection
│       ├── integer_overflow.py # Integer overflow / underflow
│       ├── tx_origin.py        # tx.origin authentication misuse
│       ├── selfdestruct.py     # Unprotected selfdestruct
│       ├── weak_randomness.py  # block.timestamp / blockhash misuse
│       └── unchecked_calls.py  # Ignored .call()/.send() return values
├── simulation/
│   └── simulate.py             # Ganache blockchain simulation
├── templates/
│   ├── index.html              # Upload page
│   └── report.html             # Vulnerability report
├── static/
│   ├── css/style.css
│   └── js/main.js
└── samples/
    ├── reentrancy.sol          # HIGH — classic DAO attack pattern
    ├── overflow.sol            # MEDIUM — pre-0.8 integer overflow
    ├── randomness.sol          # MEDIUM — block.timestamp lottery
    └── safe.sol                # SAFE — best-practice reference
```

---

## Vulnerability Coverage

| Vulnerability | Severity | Detection Method |
|---|---|---|
| Reentrancy Attack | HIGH | Pattern matching + CEI ordering check |
| Integer Overflow/Underflow | MEDIUM | Pragma version + SafeMath analysis |
| tx.origin Misuse | HIGH | Regex on require/if conditions |
| Unprotected Selfdestruct | CRITICAL | Brace-matched function + guard check |
| Weak Randomness | MEDIUM | block.* property usage detection |
| Unchecked Call Returns | LOW | Return value capture analysis |

---

## Tech Stack

| Tool | Purpose |
|---|---|
| Python 3 | Core scanner engine |
| Flask | Web interface |
| Regex + AST heuristics | Vulnerability detection |
| Ganache (via npx) | Local blockchain simulation |
| web3.py | Blockchain interaction |

---

## Author

**Kru Infosec** — Cybersecurity research & smart contract security analysis.
