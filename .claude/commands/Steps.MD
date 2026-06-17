# SAST Agent — Build Plan

## Goal
Build an LLM-powered SAST agent that replaces traditional Java SAST tools.
Target: https://github.com/appsecco/dvja
Scope: OWASP Top 10, secure coding vulnerabilities, operational metrics. (SCA is out of scope.)

---

## Architecture

```
Orchestrator Agent
├── Crawler Agent       → maps file structure, entry points
├── SAST Agent(s)       → per-class/per-method vulnerability detection
│   └── Taint Agent     → source-to-sink analysis across call graph
├── Validator Agent     → filters low-confidence / duplicate findings
└── Report Agent        → SARIF output + metric aggregation
```

---

## Milestone 1 — Foundation & Ground Truth

**Goal:** Establish baseline accuracy before building the full pipeline.

- [x] Clone DVJA repo locally
- [x] Document DVJA's known vulnerabilities (ground truth list)
- [ ] Run `/sast:crawl` against DVJA — verify `crawl-output.json` is produced with correct entry points
- [ ] Run `/sast:find-vulns` (once built) against DVJA findings
- [ ] Compare findings vs known vulnerability list
- [ ] Compute initial precision / recall
- [ ] Identify the OWASP category where the skill performs best → focus there first

**Verify:** `/sast:find-vulns` produces structured JSON findings with CWE + OWASP mapping.

---

## Milestone 2 — Create Skills

**Goal:** Define and scaffold all skills as `.claude/commands/sast/` prompt files.

- [ ] `/crawl` — walk repo, build file map, write entry points to `crawl-output.json`
- [ ] `/find-vulns` — per-file/per-method analysis, reads from `crawl-output.json`, writes `findings.json`
- [ ] `/taint-trace` — source-to-sink analysis, reads call graph, appends to `findings.json`
- [ ] `/validate-findings` — deduplicates, scores confidence, flags likely FPs in `findings.json`
- [ ] `/scan-report` — reads `findings.json`, outputs SARIF + markdown summary
- [ ] `/generate-fix` — standalone, takes a single finding as input, outputs before/after diff
- [ ] `/scan-metrics` — wraps any skill invocation, captures tokens / time / cost
- [ ] `/sast-full-scan` — orchestrator, chains all skills above in order

**Verify:** Each skill file exists, has a defined input/output contract, and can be invoked independently.

---

## Milestone 3 — OWASP Top 10 Coverage

**Goal:** Explicit detection rules mapped to each OWASP category.

| OWASP Category | Java Patterns to Detect |
|---|---|
| A01 Broken Access Control | Missing auth checks, IDOR, path traversal |
| A02 Cryptographic Failures | Weak ciphers (MD5/SHA1), hardcoded keys, plaintext storage |
| A03 Injection | SQL, LDAP, OS command, XPath injection |
| A04 Insecure Design | Missing rate limits, trust boundary violations |
| A05 Security Misconfiguration | Default creds, debug enabled, verbose errors |
| A06 Vulnerable Components | Out of scope (SCA removed) |
| A07 Auth Failures | Weak session mgmt, no account lockout, JWT misuse |
| A08 Integrity Failures | Insecure deserialization, untrusted data in ObjectInputStream |
| A09 Logging Failures | Sensitive data in logs, missing audit trails |
| A10 SSRF | User-controlled URLs in HTTP clients, DNS lookups |

- [ ] Implement detection prompt per OWASP category
- [ ] Test each category against DVJA's known instances
- [ ] Track per-category precision/recall

**Verify:** `/find-vulns` finds at least one known instance of each OWASP category present in DVJA.

---

## Milestone 4 — Metrics & Observability

**Goal:** Track operational and quality metrics per scan.

### Operational Metrics
- [ ] Token usage (input / output / total) per scan
- [ ] Scan duration (total + per skill)
- [ ] Cost estimate per scan

### Quality Metrics
- [ ] Finding count by severity (Critical / High / Medium / Low)
- [ ] False positive rate (after developer triage)
- [ ] Fix acceptance rate (fixes applied vs suggested)
- [ ] Coverage % (files/methods analyzed vs total)
- [ ] Delta vs last scan (new / resolved / recurring findings)

### Output per finding
```json
{
  "cwe": "CWE-89",
  "owasp": "A03:2021",
  "file": "UserController.java",
  "line": 42,
  "sink": "executeQuery()",
  "source": "request.getParameter()",
  "confidence": 0.87,
  "cvss": 8.1,
  "fix_suggestion": "...",
  "false_positive": null
}
```

- [ ] Persist metrics to JSON/SQLite per scan run
- [ ] Build simple summary report (markdown or HTML)

**Verify:** After each scan, a metrics file is written with all fields populated.

---

## Milestone 5 — Fix Generation & Effectiveness

**Goal:** Generate, track, and measure fix quality.

- [ ] `/generate-fix` skill — per finding, generate a secure code replacement
- [ ] Fixes include: explanation, before/after diff, CWE reference
- [ ] Track: fix accepted, fix rejected, fix caused regression
- [ ] Compute fix effectiveness rate = accepted / (accepted + rejected)

**Verify:** Fix suggestions apply cleanly as patches. Effectiveness rate tracked over time.

---

## Milestone 6 — CI/CD Integration

**Goal:** Usable in a real development workflow.

- [ ] SARIF output format (integrates with GitHub Security tab, VS Code)
- [ ] Incremental scan mode — analyze only `git diff` files + their callers
- [ ] GitHub Actions workflow template
- [ ] Baseline mode — suppress known/accepted findings, alert on new ones

**Verify:** A PR to DVJA triggers the agent and posts findings as GitHub Security alerts.

---

## Known Risks & Mitigations

| Risk | Mitigation |
|---|---|
| LLM non-determinism | temperature=0, structured prompts, cache results |
| High false positive rate | Taint agent + Validator agent filter; calibrate on DVJA ground truth |
| Context window limits on large repos | Chunking by file/method; incremental mode |
| Weak cross-file taint analysis | Hybrid: Semgrep/JavaParser for structure + LLM for contextual reasoning |
| Cost blowup on large scans | Token budget per scan; incremental mode as default |

---

## Hybrid Strategy (LLM + Rule Engine)

Pure LLM SAST has high FP rates on cross-file flows. Recommended approach:
- **Semgrep / JavaParser** — structural AST-level taint tracking (fast, deterministic)
- **LLM** — contextual reasoning ("is this actually exploitable?") + fix generation

---

## Next Step

Start with **Milestone 1**:
1. Clone DVJA
2. List its known vulnerabilities
3. Write the first single-agent scan
4. Measure precision/recall against ground truth
