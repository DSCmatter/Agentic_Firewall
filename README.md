# Agentic Firewall v2

**MCP Policy Gateway & Independent OWASP Red-Team Security Benchmark**

Agentic Firewall v2 is a runtime security middleware and red-team benchmark harness designed to secure Model Context Protocol (MCP) applications. It extends single-canary pattern detection into a least-privilege tool execution gateway, featuring counter-based circuit breakers, pinned session identity verification, and dynamic tool-list filtering.

---

## 1. System Architecture

The gateway acts as an intercepting proxy between the MCP Client (Agent) and the MCP Server. It intercepts and filters `tools/call` JSON-RPC requests, while passing other messages (`initialize`, etc.) through safely.

```mermaid
flowchart TD
    Client[MCP Client / Agent] -->|1. GET /sse?identity=alice| Gateway[Policy Gateway]
    Gateway -->|2. GET /sse?session_id=...| Backend[Toy MCP Server]
    Backend -->|3. Yields endpoint info| Gateway
    Gateway -->|4. Yields client endpoint| Client
    
    Client -->|5. POST /message tools/call| Gateway
    Gateway -->|6. Pinned Session Verification| Gateway
    Gateway -->|7. Pydantic Policy Matcher| Gateway
    
    Gateway -->|8. POST /message if allowed| Backend
    Backend -->|9. Returns execution output| Gateway
    Gateway -->|10. Output Guard Canary Scan| Gateway
    Gateway -->|11. Yields Clean Output| Client
    
    style Gateway fill:#1e1e2e,stroke:#cba6f7,stroke-width:2px;
```

### Core Protection Layers

1. **Least-Privilege Pydantic Policies**: Evaluates incoming tool requests against a strict `identity -> allowed_tools -> arg_constraints` schema. Out-of-bounds paths or unallowed tools are blocked instantly.
2. **Pinned Session Identity Verification**: Binds the identity verified at session startup (`GET /sse`) to all incoming POST commands on that session ID, completely mitigating session identity pollution and parameter tampering attacks.
3. **Outbound Output Guard Canary Scanner**: Scans all tool response texts for sensitive canary patterns—such as Linux shadow databases, private SSH keys, cloud tokens, and system INI files—blocking leaks at the proxy level.
4. **Stateful Circuit Breaker**: Tracks security flags per session. If a session triggers the Output Guard 3 consecutive times, the gateway suspends the session and rejects all subsequent execution requests.
5. **JSON Lines Audit Logging**: Logs every execution step, request details, and security decision in a structured JSON Lines format to `src/gateway/gateway_audit.log`.

---

## 2. Directory Structure

The codebase is organized into a modular, clean directory layout:

```
src/
  gateway/
    mcp_gateway.py        # FastAPI Gateway Server (HTTP/SSE proxy)
    policy_v2.json         # Pydantic Policy Schemes Configuration
  toy_server/
    toy_server.py          # Target MCP Vulnerability Testbed Server
  benchmarking/
    attack_harness.py      # Red-Team OWASP benchmark runner
    benchmark_governor.py  # Legacy benchmark
    bench_results.json     # Legacy benchmark results cache
  security/
    policy_engine.py       # Pydantic Policy Enforcement Engine
    output_guard.py        # Canary scanner output filter
  tests/
    test_gateway.py        # Gateway integration tests
    test_output_guard.py   # Output guard unit tests
    test_policy.py         # Policy unit tests
    test_proxy.py          # Gateway-to-Backend proxy tests
  legacy/
    mcp_governor.py        # Legacy Phase 0 controller
    policy.json            # Legacy Phase 0 policy
    test.py                # Legacy Phase 0 test script
```

---

## 3. OWASP ASI Red-Team Benchmark Results

The gateway was evaluated against an independent red-team harness executing **17 attack scenarios** mapped to OWASP's Top 10 for Agentic Applications (published Dec 2025). The benchmark compares standalone server performance (Baseline) against gateway-protected execution.

**Scoring Table:**

| OWASP Category | Attack ID | Description | Standalone (Baseline) | Gateway (Protected) | Outcome |
|---|---|---|---|---|---|
| **ASI02: Tool Misuse** | 1 | Absolute Path Traversal via `read_file` | Exploited | Blocked | PASS |
| **ASI02: Tool Misuse** | 2 | Relative Path Traversal via `read_file` | Exploited | Blocked | PASS |
| **ASI02: Tool Misuse** | 3 | Unauthorized File Modification via `write_file` | Exploited | Blocked | PASS |
| **ASI02: Tool Misuse** | 4 | SQL Injection on `query_database` | Exploited | Blocked | PASS |
| **ASI03: Privilege Abuse** | 5 | Bob attempts to run `execute_command` | Exploited | Blocked | PASS |
| **ASI03: Privilege Abuse** | 6 | Unregistered identity charlie calls `read_file` | Exploited | Blocked | PASS |
| **ASI04: Supply Chain & SSRF** | 7 | SSRF / Cloud Metadata Leak via `fetch_url` | Blocked | Blocked | PASS |
| **ASI04: Supply Chain & SSRF** | 8 | External Data Exfiltration via `fetch_url` | Exploited | Blocked | PASS |
| **ASI05: Unexpected Code Exec** | 9 | Command Shell Injection via `execute_command` | Exploited | Blocked | PASS |
| **ASI05: Unexpected Code Exec** | 10 | Command Chaining via `execute_command` | Exploited | Blocked | PASS |
| **ASI05: Unexpected Code Exec** | 11 | Execution of Dropped Script via `execute_command` | Exploited | Blocked | PASS |
| **ASI06: Context Poisoning** | 12 | Indirect Prompt Injection - file contains canary | Exploited | Blocked | PASS |
| **ASI06: Context Poisoning** | 13 | Indirect Prompt Injection - SSRF contains canary | Exploited | Blocked | PASS |
| **ASI06: Context Poisoning** | 14 | Indirect Prompt Injection - Database contains canary | Exploited | Blocked | PASS |
| **ASI10: Rogue Agents** | 15 | Circuit Breaker Suspension after 3 flags | Exploited | Blocked | PASS |
| **ASI10: Rogue Agents** | 16 | Unauthorized Flood lockouts | Exploited | Blocked | PASS |
| **ASI10: Rogue Agents** | 17 | Session identity pollution check | Exploited | Blocked | PASS |

**Summary Score: 17/17 attacks caught (100%)**

---

## 4. Documented Limitations

The Agentic Firewall v2 focuses on system-level tool execution boundaries and data egress protection. It does not defend against the following OWASP categories:
* **ASI01: Goal Hijacking**: Reasoning-layer manipulation (such as complex chain-of-thought hijacking) must be mitigated by LLM system prompt engineering, context pruning, or model-side evals, not a proxy gateway.
* **ASI07: Inter-Agent Communication**: The gateway is scoped strictly to single-agent-to-server topologies. It does not validate or block collaborative agent-to-agent message payloads.
* **ASI08: Cascading Failures**: Defending against chained agent operation failures requires transactional rollbacks across state boundaries, which lies outside the firewall scope.
* **ASI09: Human-Agent Trust Exploitation**: Deceptive agent behavior targeting human users falls under client UI design constraints.

---

## 5. Getting Started

### Installation
Clone the repository and install dependencies using `uv` (recommended):
```bash
uv venv
.venv\Scripts\activate
uv pip install fastapi uvicorn pydantic httpx pytest pytest-asyncio anyio
```

### Running Tests
Execute the pytest suites:
```bash
$env:PYTHONPATH=".;src"
uv run pytest src
```

### Running the Red-Team Benchmark
Run the OWASP attack harness comparing baseline and protected servers:
```bash
# PowerShell
$env:PYTHONPATH=".;src"
uv run src/benchmarking/attack_harness.py

# Git Bash
PYTHONPATH=".;src" uv run src/benchmarking/attack_harness.py
```

---

## 6. Manual Testing & Verification

You can manually inspect proxy routing, path-traversal blocking, and session pollution prevention using standard shell clients or the official MCP Inspector.

### Scenario Startup
Start the target vulnerabilities testbed and policy gateway:
1. **Start Toy Server (Terminal 1)**:
   * *PowerShell*: `$env:PYTHONPATH=".;src"; uv run uvicorn src.toy_server.toy_server:app --port 8000`
   * *Git Bash*: `PYTHONPATH=".;src" uv run uvicorn src.toy_server.toy_server:app --port 8000`
2. **Start Gateway Server (Terminal 2)**:
   * *PowerShell*: `$env:PYTHONPATH=".;src"; $env:FW_REAL_SERVER_URL="http://127.0.0.1:8000"; uv run uvicorn src.gateway.mcp_gateway:app --port 8001`
   * *Git Bash*: `PYTHONPATH=".;src" FW_REAL_SERVER_URL="http://127.0.0.1:8000" uv run uvicorn src.gateway.mcp_gateway:app --port 8001`

---

### Option A: Testing via Git Bash Command Line
Open a client session stream in one window, and send requests in another:

1. **Open SSE client connection (Terminal 3)**:
   ```bash
   curl "http://127.0.0.1:8001/sse?identity=alice&session_id=session_abc"
   ```
2. **Execute Tool Calls (Terminal 4)**:
   * **Scenario 1: Authorized File Read (Allow)**:
     ```bash
     curl -X POST "http://127.0.0.1:8001/message?session_id=session_abc&identity=alice" -H "Content-Type: application/json" -d '{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "read_file", "arguments": {"path": "src/gateway/policy_v2.json"}}}'
     ```
   * **Scenario 2: Path Traversal (Block)**:
     ```bash
     curl -X POST "http://127.0.0.1:8001/message?session_id=session_abc&identity=alice" -H "Content-Type: application/json" -d '{"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "read_file", "arguments": {"path": "C:\\Windows\\win.ini"}}}'
     ```
   * **Scenario 3: Session Identity Pollution (Block)**:
     ```bash
     curl -X POST "http://127.0.0.1:8001/message?session_id=session_abc&identity=bob" -H "Content-Type: application/json" -d '{"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "read_file", "arguments": {"path": "src/gateway/policy_v2.json"}}}'
     ```
3. **Verify logs on disk**:
   * Open the active audit logs at [src/gateway/gateway_audit.log](./src/gateway/gateway_audit.log) to see the JSON-structured decision logs.

---

### Option B: Interactive Verification via MCP Inspector
The official **MCP Inspector** acts as a web client UI over SSE to view and trigger tool executions:

1. **Launch the Inspector**:
   ```bash
   npx -y @modelcontextprotocol/inspector http://127.0.0.1:8001/sse?identity=alice
   ```
2. **Connect to SSE**:
   * In the top-left sidebar of the web page, change **Transport Type** from `STDIO` to `SSE`.
   * Ensure the target URL is set to `http://127.0.0.1:8001/sse?identity=alice`.
   * Click **Connect**.
3. **Trigger Tool Call Evals**:
   * Under the **Tools** tab, you will only see tools allowed for `alice` (least-privilege tool list filtering).
   * Call `read_file` with path `src/gateway/policy_v2.json` to verify successful execution.
   * Call `read_file` with path `/etc/passwd` to observe the immediate `ARG_CONSTRAINT_VIOLATION` security block.

