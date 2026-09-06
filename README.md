# Agentic Firewall

**MCP security middleware + automated security testing for AI agents.**

Agentic Firewall sits between an AI agent or MCP client and an MCP server. It
can enforce runtime policies and automatically test the server's tool-use
attack surface with 17 OWASP ASI scenarios. It runs locally and sends no
telemetry.

## Why

MCP gives agents access to tools, but the connection does not by itself
enforce least privilege. A compromised tool, prompt injection, or confused
identity can lead to unauthorized tool use, privilege abuse, path traversal,
command execution, data exfiltration, or session identity abuse.

## Architecture

```text
AI Agent / MCP Client
          |
          v
  Agentic Firewall
          |
          v
       MCP Server
```

The runtime firewall provides:

- least-privilege tool policies;
- session identity binding;
- argument and sandbox path constraints;
- output guard checks for sensitive or injected content;
- a circuit breaker for repeated security flags; and
- structured audit logging.

## Quickstart

Install the released package and scan the built-in benchmark:

```bash
python -m pip install agentic-firewall
agentic-firewall scan
```

The scan runs all 17 scenarios and reports a Security Score, Attack Coverage,
statuses, findings, and remediation guidance. The default target is the local
reference benchmark; no MCP server setup is required.

For repository development, use:

```bash
uv sync
uv run agentic-firewall scan
```

## Scanner

Run `agentic-firewall scan` against the built-in benchmark or a real MCP
target. Available options are:

| Option | Purpose |
| --- | --- |
| `--server-url URL` | Scan an HTTP/SSE MCP server. The URL must expose `<URL>/sse`. |
| `--server-cmd JSON` | Scan a local stdio MCP server using a JSON argv array. |
| `--format rich\|json` | Render terminal output or a machine-readable report. |
| `--output PATH` | Write the JSON report to a file. |
| `--quiet`, `-q` | Show only score, coverage, and findings. |
| `--no-progress` | Disable the animated progress display. |
| `--fail-on critical\|high\|medium\|low` | Exit 1 when a vulnerability at or above the threshold is found. |

### Scan an MCP server

```bash
# HTTP/SSE target
agentic-firewall scan --server-url http://127.0.0.1:8000

# Local stdio target
agentic-firewall scan --server-cmd '["python", "my_mcp_server.py"]'
```

HTTP/SSE and stdio are the supported scanner target transports. WebSocket
support in the gateway does not make WebSocket a supported scanner target.
Embedded credentials and query strings in `--server-url` are rejected.
Applicability is based on declared tool names; semantic compatibility with a
tool's input schema is not fully validated.

### Successful scan

```text
Security Score   100/100 (A)
Attack Coverage  17/17
Vulnerabilities  0
```

### Vulnerability findings

For a vulnerable target, each finding includes the severity, attack name,
OWASP category, protection source, evidence, and remediation. `VULNERABLE`
means the attack demonstrated a vulnerability against the protected target;
it is not merely an informational result.

```text
CRITICAL  Command Shell Injection via execute_command  Attack #9
          OWASP:       ASI05: Unexpected Code Exec
          Protection:  NONE
          Evidence:    exploit succeeded
          Remediation: revoke execute_command for untrusted identities
```

### Result statuses

- `PASS`: the attack was resisted according to the benchmark criteria.
- `VULNERABLE`: the attack succeeded against the protected target.
- `ERROR`: a transport, timeout, or execution failure prevented a result. It
  is not a vulnerability.
- `SKIPPED`: the test was intentionally omitted.
- `NOT_APPLICABLE`: the target does not expose the required tool. It is not a
  successful security test.

### Security Score and Attack Coverage

The score is a deterministic, severity-weighted score over applicable,
evaluated tests (`PASS` and `VULNERABLE`). The weights are Critical = 10,
High = 6, Medium = 3, and Low = 1. The score is the weighted points earned by
passing tests divided by the maximum weighted points for the applicable
evaluated tests, rounded to a percentage. It is a measure of this benchmark's
results, not a percentage of universal security.

Attack Coverage is shown separately as `applicable tests / 17`. If any test is
`ERROR`, the scan is incomplete and the score is `N/A`; incomplete scans never
receive a numeric score. A complete scan with no applicable tests also has no
numeric score.

Protection attribution is reported as `FIREWALL`, `TARGET`, `BOTH`, `NONE`,
or `UNKNOWN` based on the observed response evidence.

## Compare scans

Save two schema 1.1 reports and compare them without contacting an MCP server:

```bash
agentic-firewall scan --format json --output before.json
agentic-firewall scan --format json --output after.json
agentic-firewall compare before.json after.json
```

Comparison uses stable `attack_id` values and reports regressions, resolved or
new vulnerabilities, severity changes, status changes, protection-source
changes, and coverage changes. Comparison JSON is available with
`--format json`.

## CI

Use JSON output and a severity gate in CI:

```bash
agentic-firewall scan --no-progress --format json --fail-on high
```

Exit codes are:

- `0`: the scan completed and the security gate was not triggered;
- `1`: an infrastructure error occurred or the security gate was triggered;
- `2`: a usage or configuration error occurred.

`--fail-on` does not change the score, findings, coverage, or JSON report.

## JSON output

Scan reports use schema version `1.1` and include stable attack IDs, target
details, score and coverage, result statuses, protection attribution, evidence,
and remediation metadata.

```json
{
  "schema_version": "1.1",
  "summary": {
    "score": 100,
    "grade": "A",
    "attack_coverage": "17/17",
    "passed": 17,
    "vulnerable": 0
  },
  "results": [
    {
      "attack_id": 1,
      "status": "PASS",
      "protection_source": "FIREWALL",
      "evidence": {},
      "remediation": null
    }
  ]
}
```

## Runtime Firewall

The scanner and runtime firewall are complementary. The runtime side exposes
a policy engine for tool authorization, identity and session binding,
sandbox/path constraints, an output guard, a circuit breaker, and audit logs.
The gateway supports HTTP/SSE and WebSocket client connections and can proxy
HTTP/SSE or local stdio backends. The scanner's supported target transports
remain HTTP/SSE and stdio.

## Attack Coverage

The 17 current scenarios are grouped by OWASP ASI category:

**ASI02: Tool Misuse**

1. Absolute Path Traversal via `read_file`
2. Relative Path Traversal via `read_file`
3. Unauthorized File Modification via `write_file`
4. SQL Injection on `query_database`

**ASI03: Privilege Abuse**

5. Bob attempts to run `execute_command`
6. Unregistered identity charlie calls `read_file`

**ASI04: Supply Chain & SSRF**

7. SSRF / Cloud Metadata Leak via `fetch_url`
8. External Data Exfiltration via `fetch_url`

**ASI05: Unexpected Code Exec**

9. Command Shell Injection via `execute_command`
10. Command Chaining via `execute_command`
11. Execution of Dropped Script via `execute_command`

**ASI06: Context Poisoning**

12. Indirect Prompt Injection - file contains canary
13. Indirect Prompt Injection - SSRF contains canary
14. Indirect Prompt Injection - Database contains canary

**ASI10: Rogue Agents**

15. Circuit Breaker Suspension after 3 security flags
16. Unauthorized Flood test
17. Session identity pollution check

## Limitations and Threat Model

Agentic Firewall focuses on MCP tool execution boundaries and output/data
egress controls. It does not attempt to solve all LLM reasoning-layer attacks,
all agentic attack classes, inter-agent communication security, every possible
MCP server or tool schema, or universal AI security. In particular, the
benchmark does not cover all OWASP agentic-application categories, and tool
applicability for third-party servers is based on declared names rather than
full semantic schema validation. Local stdio commands run with the invoking
user's operating-system permissions.

## Development

```bash
uv sync
uv run pytest
```

The existing [launch assets](src/docs/LAUNCH_ASSETS.md) contain release and
community-positioning material. The [user validation framework](src/docs/USER_VALIDATION_FRAMEWORK.md)
documents the project's local-first feedback approach. Manual gateway
verification is intended for development and is not required for normal scans.

## Release and Roadmap

The current release is **v0.1.1**, available on PyPI under the MIT license.
Future direction will be guided by real-world developer feedback, MCP
compatibility reports, and security findings. The project does not promise a
SaaS dashboard, billing system, or universal security platform.
