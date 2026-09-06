# USER VALIDATION FRAMEWORK

**Goal:** Learn what real developers need from Agentic Firewall without invasive telemetry.

## Data Collection Strategy (Non-Invasive)

### Do NOT:
- ❌ Add telemetry or analytics SDKs
- ❌ Phone home with usage data
- ❌ Track scans or target servers
- ❌ Collect personally identifiable information
- ❌ Use silent data collection

### DO:
- ✅ Monitor public signals (GitHub activity, issues, downloads)
- ✅ Respond to user feedback and questions
- ✅ Read reported issues and PRs
- ✅ Engage in GitHub Discussions
- ✅ Track feature requests and patterns
- ✅ Monitor MCP compatibility reports
- ✅ Document user reports and use cases

---

## Monitoring Channels

### 1. GitHub Issues
**What to track:**
- Bug reports (category: implementation, false positives, false negatives)
- Feature requests (category: what's requested, how often, by whom)
- MCP compatibility issues (category: which servers, what tools)
- Onboarding friction (category: installation, CLI clarity, documentation)
- CI integration questions

**Signals to look for:**
- Repeated issues on the same topic (indicates pain point)
- Severity of reported issues (blocker vs. nice-to-have)
- Resolution time (indicates importance)

### 2. GitHub Discussions
**What to track:**
- Questions about usage
- Requests for examples
- Discussions of security concerns
- Integration patterns
- MCP server recommendations

### 3. Pull Requests
**What to track:**
- Community contributions (indicates engagement and maturity)
- Types of changes (fixes, features, docs)
- Code quality and understanding

### 4. GitHub Metrics (Public)
- ⭐ Stars (indicates interest level)
- 🔄 Forks (indicates adoption intent)
- 👀 Watches (indicates following the project)
- 📥 Open issues (indicates roadmap pressure)

### 5. Package Manager Downloads
**Where available:**
- PyPI download stats (via public API)
- Pip install trends
- Conda if published

### 6. Social Signals
- HN discussion thread (karma, comments, criticisms)
- Reddit discussion thread (votes, conversation depth)
- ProductHunt (makers responses, feature requests)
- Twitter/X mentions and replies

---

## Feedback Classification

When gathering feedback, classify into these categories:

### Installation & Onboarding (Immediate)
- Could not install
- Installation unclear
- Getting started unclear
- First scan confusing
- Help text insufficient

### MCP Compatibility (High Priority)
- Server X not scanning
- Tool Y not recognized
- Transport issue (HTTP/SSE vs stdio)
- Preflight failure
- Tools list filtering unexpected

### Benchmark Quality (High Priority)
- Attack doesn't make sense
- Attack doesn't apply to server type
- Result interpretation unclear
- Missing attack scenario
- False positive
- False negative

### Reporting & Output
- JSON schema confusion
- Score calculation unclear
- Remediation guidance insufficient
- Missing output format
- Comparison output confusing

### CI Integration (Medium Priority)
- Exit codes unclear
- GitHub Actions setup questions
- CI gate semantics confusion
- Artifact storage questions
- Regression detection questions

### Runtime Firewall (Lower Priority for v0.1.0)
- Policy configuration too complex
- Identity binding unclear
- Circuit breaker behavior unexpected
- Output guard false positives
- Permission/capability issues

### Feature Requests (To Classify)
- Persistent scan history
- Custom policy editor
- Webhook notifications
- Slack integration
- Multiple MCP servers simultaneously
- Policy presets
- More attack scenarios
- Broader MCP ecosystem support

---

## Stage 2 Decision Criteria

### Evidence That Justifies Major Investment

✅ **Validate Stage 2 if:**

1. **Repeated Requests for Custom Policies**
   - Multiple users ask for policy customization beyond current Pydantic schema
   - Use cases suggest real businesses need bespoke configurations
   - Evidence: 5+ issues/discussions from different organizations

2. **Persistent Scan History Demand**
   - Multiple users want scan archive/trends over time
   - Organizations want to track security posture over quarters
   - CI/CD integrations suggest this is critical for compliance
   - Evidence: 3+ issues specifically asking for persistent history

3. **Heavy CI/CD Usage**
   - Repeated questions about CI gate semantics
   - Custom GitHub Actions workflows in the wild
   - High failure rate on specific CI platforms
   - Evidence: 3+ organizations reporting repeated CI usage patterns

4. **Broad MCP Ecosystem Adoption**
   - Users scanning diverse MCP servers (Anthropic's, custom, third-party)
   - Compatibility issues across server types
   - Requests for pre-built server profiles
   - Evidence: Active use across 5+ different MCP server implementations

5. **Centralized Findings Demand**
   - Organizations want to aggregate findings across multiple scan targets
   - Teams need shared reports and compliance artifacts
   - Evidence: 3+ organizations asking for multi-target aggregation

6. **Repeated Scanner Usage**
   - Users running scans regularly (not one-time validation)
   - Integration into existing security workflows
   - High re-run rates suggesting automation
   - Evidence: Reports of weekly/monthly scanning patterns

7. **Community Contributions**
   - PR submissions for new attack scenarios
   - Community policy contributions
   - MCP server integration PRs
   - Evidence: 5+ meaningful PRs from community

### Evidence That Suggests DIFFERENT Direction

⚠️ **Change Direction if:**

1. **Majority Demand is LLM-Layer Security**
   - Most issues are about prompt injection, goal hijacking, reasoning manipulation
   - Tool boundaries are less important than model security
   - Conclusion: Build LLM-focused security instead

2. **Users Want "Set It and Forget It" (Not Scanning)**
   - Primary use case is runtime protection, not testing
   - Scan frequency is very low, but runtime deployment is high
   - Conclusion: Focus on the gateway as a service, not the benchmark

3. **No Traction After 6 Months**
   - Minimal GitHub engagement
   - No third-party users reported
   - No external contributions
   - Conclusion: Either pivot or conclude this is a niche problem

4. **MCP Ecosystem Stalls**
   - MCP adoption by LLM providers and tool developers is very slow
   - Few real MCP servers in the wild
   - Anthropic/OpenAI move to different standards
   - Conclusion: Build for whatever becomes the real standard

5. **Generic LLM Scanners Dominate**
   - Market consolidates around generic LLM security platforms
   - MCP-specific angle becomes irrelevant
   - Conclusion: Pivot or become a component of larger platform

---

## Stage 2 Investment Hypotheses (To Test)

### H1: Developers need automated MCP security testing
- Test by: Measure adoption, scan frequency, GitHub engagement
- Validate if: 50+ monthly active users running scans regularly

### H2: Organizations need policy enforcement at runtime
- Test by: Track CI gate adoption, policy customization requests
- Validate if: 10+ organizations report using runtime gateway

### H3: Security teams need regression detection
- Test by: Track comparison feature usage, scan archival requests
- Validate if: 5+ organizations report using compare for CI/CD

### H4: Custom policies are the long-term value
- Test by: Track policy customization requests vs. default policy usage
- Validate if: 30% of users customize policies beyond defaults

### H5: MCP is durable as a standard
- Test by: Monitor MCP adoption by LLM providers and tool developers
- Validate if: 3+ major LLM providers officially support MCP by H2 2025

---

## Success Metrics (v0.1.0 → Stage 2)

| Metric | Threshold | Timeframe |
|--------|-----------|-----------|
| GitHub Stars | 500+ | 6 months |
| Monthly Active Users | 50+ | 6 months |
| Feature Requests (Unique Themes) | 5+ repeated | 6 months |
| Community PRs | 5+ | 6 months |
| Organizations Using in CI | 10+ | 6 months |
| Organizations with Custom Policies | 5+ | 6 months |
| HN/Reddit positive sentiment | >80% | Launch |

---

## Questions to Answer via User Feedback

1. **Is MCP the right target?** Or should we pivot to LLM SDK security, plugin security, etc.?
2. **Is the benchmark realistic?** Are the 17 attacks representative of real threats?
3. **Is the scoring useful?** Or do users want just a pass/fail?
4. **Do users need runtime protection?** Or is testing sufficient?
5. **Is the gateway too complex?** Or do organizations want more customization?
6. **What are the failure modes?** False positives? False negatives?
7. **Who actually uses this?** Security teams? Platform teams? Developers?
8. **What's the real value?** Compliance? Risk reduction? Development velocity?

---

## Review Cadence

- **Monthly:** Check GitHub issues, discussions, and PRs
- **Quarterly:** Aggregate feedback, identify themes, update roadmap
- **Bi-annually:** Major decision point (continue, pivot, or consolidate)

