# Changelog

## 0.1.0 - Initial public release

Agentic Firewall is an installable MCP policy gateway and independent security benchmark for evaluating tool-use boundaries and data egress controls.

### Included

- `agentic-firewall scan` with 17 OWASP ASI attack scenarios.
- Built-in benchmark scanning plus HTTP/SSE and local stdio MCP targets.
- PASS, VULNERABLE, ERROR, SKIPPED, and NOT_APPLICABLE result statuses.
- Severity-weighted scoring, attack coverage, protection attribution, findings, and remediation metadata.
- Rich terminal output, quiet and no-progress modes, JSON reports, and `--fail-on` CI gates.
- Bounded MCP inputs, terminal-safe diagnostics, and subprocess cleanup.

### Limitations

The benchmark evaluates the supported gateway policies and reference attack scenarios. It does not provide universal MCP security, reason about model intent, validate arbitrary tool schemas semantically, or cover all OWASP agentic-application categories. Local stdio commands run with the invoking user's operating-system permissions.