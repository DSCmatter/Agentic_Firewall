# LAUNCH ASSETS - Agentic Firewall v0.1.0

## GitHub Repository Description (160 characters max)

**Option A (concise):**
"MCP security middleware + automated testing for AI agents. Runtime protection & red-team OWASP benchmark."

**Option B (longer):**
"MCP policy gateway & independent red-team security benchmark for AI agents. 17 OWASP attack scenarios."

---

## GitHub Release Notes (v0.1.0)

### 🚀 Agentic Firewall v0.1.0 — Initial Public Release

**What is Agentic Firewall?**

Agentic Firewall is a runtime security middleware and automated security testing framework for Model Context Protocol (MCP) applications. It acts as an intercepting proxy between an AI agent and any MCP server, enforcing tool-use boundaries and detecting data egress violations.

**Two Core Capabilities:**

1. **Runtime Protection** — Policy-based tool filtering, least-privilege constraints, and canary-based output guards.
2. **Security Testing** — Automated red-team benchmark with 17 OWASP ASI attack scenarios and regression comparison.

**What's Included:**

- `agentic-firewall scan` — Execute 17 OWASP ASI attacks against any MCP target
- Real MCP target scanning — HTTP/SSE and local stdio support
- Security Score + Attack Coverage metrics
- Vulnerability findings with remediation guidance
- JSON reports (schema v1.1) for integration and archival
- Scan regression comparison (`agentic-firewall compare`)
- CI security gating (`--fail-on critical|high|medium|low`)
- 92 tests, 100% pass rate

**Getting Started (30 seconds):**

```bash
git clone https://github.com/DSCmatter/Agentic_Firewall.git
cd Agentic_Firewall
uv sync
uv run agentic-firewall scan
```

**Scan an MCP Server:**

```bash
# HTTP/SSE MCP server
uv run agentic-firewall scan --server-url http://127.0.0.1:8000

# Local stdio MCP server
uv run agentic-firewall scan --server-cmd '["python", "my_mcp_server.py"]'
```

**CI Integration:**

```bash
uv run agentic-firewall scan --no-progress --format json --fail-on high
```

**Key Differentiators:**

- **MCP-focused** — Specifically designed for Model Context Protocol agents
- **Runtime + Testing** — Both policy enforcement and vulnerability discovery
- **Real targets** — Scans actual MCP servers, not just synthetic examples
- **Regression detection** — Compare scans to identify security regressions
- **CI-native** — Exit codes, JSON reports, and security gates for pipeline integration
- **No SaaS** — Runs locally without cloud dependency or telemetry

**Limitations:**

- Focuses on tool execution boundaries and output validation
- Does not defend against LLM reasoning layer attacks (e.g., goal hijacking)
- Designed for single-agent-to-server topologies
- Does not validate semantic tool compatibility

**Benchmark Coverage:**

Across 17 scenarios spanning OWASP ASI02–ASI10:

- Path traversal attacks (absolute and relative)
- SQL injection and NoSQL manipulation
- Command injection via tool parameters
- Session identity pollution
- Unauthorized tool access
- Output guard evasion attempts
- Circuit breaker test (session suspension)

**Architecture:**

The gateway acts as an intercepting proxy with:

1. Pinned session identity verification
2. Pydantic policy engine (per-identity tool allow-lists)
3. Argument constraint enforcement (path sandboxing)
4. Output guard canary scanner (sensitive data detection)
5. Counter-based circuit breaker (session suspension)

**Testing:**

```bash
uv run pytest  # 92 tests, ~2 minutes
```

**Status & Next:**

This is **Stage 1** — a production-ready security testing framework designed to gather real-world usage evidence. We are intentionally NOT including:

- SaaS backend, dashboard, or billing
- GitHub App or centralized policy management
- Automated remediation or LLM-based policy generation
- Broad MCP ecosystem integrations

The focus is on validating product-market fit and learning what matters most to real users.

**Feedback & Contributions:**

- GitHub Issues for bugs and feature requests
- GitHub Discussions for questions and ideas
- Pull requests welcome for bug fixes and community improvements

**License:** MIT

---

## Hacker News / Technical Forum Positioning

**Headline:**
"Agentic Firewall: MCP security middleware and automated red-team testing framework"

**Tagline:**
"Runtime policy enforcement + 17 OWASP scenario testing for AI agents, without SaaS."

**Post Content:**

I've been working on securing AI agent tool use for a few months (inspired by [Anthropic's recent research](https://www.anthropic.com/news/disrupting-AI-espionage) on AI espionage). Today I'm open-sourcing Agentic Firewall—a security middleware and automated red-team benchmark for Model Context Protocol applications.

**The Problem:**
When an LLM connects to a tool server (via MCP), there's no built-in governance layer. A compromised tool or malicious prompt can trick the agent into executing unauthorized commands, exfiltrating data, or modifying sensitive files. Security can't be an afterthought.

**What it does:**
1. Acts as an intercepting proxy between AI agents and MCP servers
2. Enforces least-privilege tool policies, sandboxed paths, and output guards
3. Runs automated security testing with 17 OWASP-inspired attack scenarios
4. Generates security scores, attack coverage metrics, and remediation guidance
5. Supports CI security gates (`--fail-on high`) and scan regression comparison

**No SaaS, no telemetry, no GitHub App.** Everything runs locally.

**Quick start:**
```bash
git clone https://github.com/DSCmatter/Agentic_Firewall.git && cd Agentic_Firewall
uv sync && uv run agentic-firewall scan
```

Runs 17 attacks in ~90 seconds against the built-in benchmark. Scan real MCP targets with `--server-url` or `--server-cmd`.

**The tricky parts:**
- Detecting data egress with string canaries (shadow files, SSH keys, cloud tokens)
- Policy expressiveness vs. simplicity (Pydantic schemas work well)
- Session identity binding to prevent cross-session pollution
- Deterministic scoring despite incomplete tool availability

**What's NOT included:**
- No SaaS, dashboard, or billing
- No LLM policy generation
- No automated remediation
- No broad MCP ecosystem pre-integration

This is **Stage 1**—a foundation for learning what real developers actually need. Feedback welcome.

---

## Reddit Positioning (r/security, r/programming, r/Python)

**Title:**
"Agentic Firewall: Open-source MCP security middleware + automated red-team benchmark for AI agents"

**Body:**

I've released [Agentic Firewall](https://github.com/DSCmatter/Agentic_Firewall) — an open-source security framework for AI agent tool use.

**Problem:** LLMs connected to tool servers (via MCP) can be tricked into executing unauthorized commands, exfiltrating data, or modifying files. There's no governance layer between the agent and the tools.

**Solution:** Agentic Firewall is both a runtime security middleware and an automated red-team benchmark:

**Runtime Protection:**
- Policy-based tool filtering (least-privilege)
- Sandboxed path constraints
- Canary-based output guards (detects shadow file leaks, SSH key exfiltration, token theft)
- Session identity pinning
- Circuit breaker for rogue agent suspension

**Security Testing:**
- 17 OWASP-inspired attack scenarios
- Real MCP target scanning (HTTP/SSE and local stdio)
- Security Score + Attack Coverage metrics
- Vulnerability findings with remediation guidance
- Scan regression comparison (before/after)
- CI security gates for pipeline integration

**No SaaS, no telemetry, runs locally.**

**Quick start:**
```bash
git clone https://github.com/DSCmatter/Agentic_Firewall.git
cd Agentic_Firewall && uv sync && uv run agentic-firewall scan
```

Runs in ~90 seconds. Scan your own MCP servers with `--server-url` or `--server-cmd`.

**GitHub:** https://github.com/DSCmatter/Agentic_Firewall
**License:** MIT | **Tests:** 92, 100% passing

Looking for early feedback on what matters most to real users.

---

## Product Hunt Positioning

**Tagline:**
"MCP security middleware + automated red-team testing for AI agents—no SaaS, no telemetry."

**Description:**

Agentic Firewall is an open-source security framework that protects AI agents from unauthorized tool use and data exfiltration.

**It does two things:**

1. **Runtime Protection** — Intercepts tool calls, enforces policies, detects data leaks
2. **Security Testing** — Runs 17 OWASP attack scenarios to find vulnerabilities

**Why it matters:** As AI agents become more autonomous, they need governance. A single prompt injection or compromised tool server can trick an agent into exfiltrating secrets, modifying databases, or executing arbitrary commands. Agentic Firewall closes that gap.

**How it works:**
- Acts as a proxy between AI agent (client) and MCP tool server (backend)
- Implements least-privilege tool policies
- Enforces sandbox path constraints
- Detects sensitive data egress (shadow files, SSH keys, tokens)
- Automatically suspends sessions showing rogue behavior

**No SaaS, no dashboard, no billing.** Everything runs locally. Open source, MIT licensed.

**Getting started:** 90-second install and first scan.

---

## Twitter / X Positioning

**Tweet 1 (Announcement):**
Introducing Agentic Firewall—an open-source MCP security middleware + red-team testing framework for AI agents. Enforces tool policies, detects data exfiltration, and runs automated vulnerability scanning. No SaaS. No telemetry. MIT licensed.

GitHub: https://github.com/DSCmatter/Agentic_Firewall

**Tweet 2 (Technical):**
How it works: Sits between your LLM and MCP tool servers. Pinned session identity + pydantic policies + output canaries + circuit breaker. 17 OWASP attack scenarios. Security scores. Regression detection. CI gates.

**Tweet 3 (Quick Start):**
```
git clone ...
uv sync && uv run agentic-firewall scan
```
Runs 17 attacks in ~90 seconds. Scan your own MCP servers with --server-url or --server-cmd.

---

## Core Value Propositions (for positioning)

**For Security Engineers:**
- Automated security testing framework with 17 real attack scenarios
- Regression detection (compare before/after scans)
- Audit logging and evidence-based findings
- Deterministic scoring for compliance and reporting

**For Platform Teams:**
- Least-privilege tool policy enforcement
- Real-time data egress detection
- Session-level circuit breaking
- JSON reports for integration with existing tools

**For AI/ML Developers:**
- Simple 3-step install, no setup required
- Scans built-in benchmark or real MCP targets
- Clear remediation guidance for vulnerabilities
- CI security gates for automated testing

**For Open Source Community:**
- MIT licensed, zero dependencies beyond standard Python stack
- 92 comprehensive tests, 100% passing
- Clear architecture, modular design
- Active development, community feedback welcome

---

## Key Differentiators (vs. Generic Security Scanning)

1. **MCP-Focused** — Specifically designed for Model Context Protocol agents, not generic LLM scanners
2. **Dual Capability** — Both runtime protection AND security testing (most tools do one or the other)
3. **Real Targets** — Scans actual MCP servers, not just synthetic examples or API specs
4. **Regression Detection** — Compare scans to catch security regressions over time
5. **CI-Native** — Deterministic exit codes, JSON reports, severity gates
6. **No Infrastructure** — Runs locally with zero cloud dependency
7. **Transparent Scoring** — Severity-weighted, evidence-based, not black-box metrics

---

## Messaging Do's and Don'ts

### DO:
✅ Say: "MCP security middleware + automated testing"
✅ Say: "17 OWASP ASI attack scenarios"
✅ Say: "Real MPC target scanning"
✅ Say: "Runtime protection + security testing"
✅ Say: "No SaaS, no telemetry"

### DON'T:
❌ Don't say: "Universal AI security solution"
❌ Don't say: "Prevents all AI-agent attacks"
❌ Don't say: "Enterprise platform"
❌ Don't say: "Managed service"
❌ Don't say: "Protects LLM reasoning layer"
❌ Don't claim: "Complete protection against all agentic threats"

### Honest Claims:
✅ "Evaluates tool execution boundaries"
✅ "Detects data egress violations"
✅ "Tests real MCP servers"
✅ "Identifies configuration weaknesses"
✅ "Provides regression detection"

