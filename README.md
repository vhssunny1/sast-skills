# SAST Skills — LLM-Powered Static Analysis Pipeline

An LLM-powered SAST pipeline built entirely as Claude Code slash commands. No compiled code, no agent framework — each capability is a prompt-driven skill that Claude executes when invoked as `/skill-name`.

Validated against **DVJA** (Java/Struts2) and **Redash** (Python/Flask + TypeScript/React). The pipeline discovered two previously-unreported critical vulnerabilities in Redash, confirmed via DAST:

| Finding | CWE | CVSS | Status |
|---|---|---|---|
| RestrictedPython sandbox escape (`python.py` `_getattr_ = getattr`) | CWE-94 | 9.9 Critical | DAST confirmed — `uid=1000(redash)` |
| Auth bypass via unsigned `X-Forwarded-Remote-User` header | CWE-287 | 9.8 Critical | DAST confirmed — full admin session, zero credentials |

---

## How It Works

Each skill is a markdown file in `.claude/commands/`. Claude Code reads it as a slash command and executes it against the target repo. Skills share state through files — no in-memory coupling.

```
/detect-language  → language-manifest.json    which skills to run
/crawl-{lang}     → crawl-output.json         file roles, routes, security_priority
/config-audit     → findings.json             dangerous defaults in .env / docker-compose
/find-vulns-{lang}→ findings.json             semantic source → sink analysis
/cross-lang-taint → findings.json             Python store → TypeScript render XSS (polyglot)
/taint-trace      → findings.json             cross-file path verification
/validate-findings→ findings.json             FP scoring + ranking
/scan-report      → scan-results.sarif        SARIF 2.1.0 for IDE / GitHub
                    scan-summary.md           human-readable report
/scan-metrics     → sast-metrics.json         append-only history
/generate-fix     → diff + explanation        per finding, on demand
```

Run everything at once:

```
/sast-full-scan <repo-path> [--ground-truth <path>]
```

---

## Skills

### Pipeline

| Skill | What it does |
|---|---|
| `detect-language` | Counts source files by extension, detects framework (Spring/Flask/Next.js/etc.), writes routing manifest for the pipeline |
| `sast-full-scan` | Orchestrator — chains all steps in order, writes intermediate snapshots to `sast-runs/<timestamp>/`. Flags: `--ground-truth`, `--skip-taint`, `--skip-config-audit` |

### Crawl — Attack Surface Mapping

| Skill | Language | What it classifies |
|---|---|---|
| `crawl` / `crawl-java` | Java | Entry points, routes, Spring/Struts/JAX-RS detection, dependency flags |
| `crawl-python` | Python | Flask/FastAPI/Django routes; `async_worker` role covers Celery, RQ, Dramatiq, Huey; `security_priority` score (1–5) per file; reads `.env` + `docker-compose` for dangerous defaults |
| `crawl-typescript` | TypeScript / JS | React/Next.js/Express routes; `security_priority` per file |

### Find Vulnerabilities — Semantic Source→Sink Reasoning

| Skill | Language | Key sinks covered |
|---|---|---|
| `find-vulns` / `find-vulns-java` | Java | SQL injection, command injection, XSS in JSP, IDOR, unvalidated redirect, weak crypto, insecure deserialization |
| `find-vulns-python` | Python | Command injection, **sandbox escape** (RestrictedPython `_getattr_` guard bypass), SSRF, path traversal, **env-gated auth bypass** (`condition` field), async queue taint, security library trust model check (Q6) |
| `find-vulns-typescript` | TypeScript / JS | DOM XSS, `dangerouslySetInnerHTML`, **Leaflet / Mapbox popup HTML injection**, open redirect, prototype pollution, SSRF, hardcoded secrets |
| `config-audit` | Any | `.env` feature flags enabled in dangerous modes, weak / default secrets, backend ports exposed past reverse proxy, debug mode, CSRF disabled |
| `cross-language-taint` | Python + TypeScript | Stored-XSS paths where Python backend writes user data → TypeScript renders it via `bindPopup()` / `innerHTML` without sanitization |

### Taint Tracing & Validation

| Skill | What it adds to `findings.json` |
|---|---|
| `taint-trace` | `taint_path[]` — hop-by-hop chain from entry point to sink. Handles async queue hops (`role: async_queue`) and feature-flag conditional guards (`conditional_protection`). Sets `taint_confirmed: true/false/null`. |
| `validate-findings` | `fp_score` (0.0 real → 1.0 false positive) and `validation_status`: `confirmed` / `likely_real` / `needs_review` / `likely_fp` |

### Reporting & Fixes

| Skill | Output |
|---|---|
| `scan-report` | `scan-results.sarif` (SARIF 2.1.0 for GitHub / VS Code) + `scan-summary.md`. Computes precision/recall when `--ground-truth` is provided. |
| `generate-fix` | Unified diff + explanation + test cases for a single finding ID |
| `scan-metrics` | Appends run stats to `sast-metrics.json` for trend tracking across scans |

### Focused Hunt Skills (standalone, no crawl required)

| Skill | Focus |
|---|---|
| `auth-audit` | Authentication and authorization checks — header-based identity, missing ownership checks, insecure session handling |
| `cmd-injection` | Deep scan for command injection — `subprocess`, `os.system`, `Runtime.exec()`, shell=True |
| `ssrf-hunt` | SSRF sinks — `requests.get(url)`, `fetch(url)`, `Repo.clone_from(url)` with unvalidated URLs |
| `path-traversal` | File path construction from user input without `resolve()` + `relative_to()` guard |
| `sandbox-escape` | Restricted execution context bypasses — `exec()` with weakened guards, `RestrictedPython` guard overrides |
| `frontend-hunt` | TypeScript/React XSS — `innerHTML`, `dangerouslySetInnerHTML`, map popup sinks, `postMessage` |
| `waf-bypass` | Encoding and evasion patterns that bypass WAF rules |

---

## Design Principles

**Read the code, not a checklist.** `find-vulns-*` skills derive findings by following data flow from source to sink in the actual code. They never consult CVE databases, ground truth files, or prior knowledge of the target repo. Every finding cites the verbatim line of evidence.

**Security library trust model.** When a security library is present, verify the implementation honours *all* of its documented trust assumptions — not just that it is imported. RestrictedPython requires `_getattr_ = safe_getattr`; if the code sets `_getattr_ = getattr` (real builtin), the sandbox is nullified. The skill reads the guard installation, not the import line.

**Feature-flag gated vulnerabilities are still vulnerabilities.** Code paths only exploitable when an env var is set (e.g. `REMOTE_USER_LOGIN_ENABLED=true`) are reported as conditional findings with a `condition` field. The flag scopes *when* they are exploitable — not whether the code is vulnerable.

**Taint crosses process and language boundaries.**
- Async queue: `entry_point → queue.enqueue(tainted) → worker → sink` crosses a Redis/RabbitMQ boundary. `taint-trace` marks the broker hop explicitly.
- Cross-language: Python stores user data in DB → TypeScript renders it in Leaflet popup → stored XSS. `cross-language-taint` matches both sides.

---

## Requirements

- **Claude Code** — [claude.ai/code](https://claude.ai/code)
- A `.git` directory at the project root (Claude Code discovers slash commands by looking for `.claude/commands/` inside a git repo)
- Point skills at your target repo — the skills themselves live here, the repo being scanned is a separate directory

---

## Usage Example

```bash
# Clone this repo
git clone https://github.com/vhssunny1/sast-skills.git
cd sast-skills

# Open Claude Code, then scan any repo
/sast-full-scan /path/to/target-repo

# With precision/recall measurement (requires a ground-truth file)
/sast-full-scan /path/to/target-repo --ground-truth /path/to/ground-truth.md

# Run individual skills
/detect-language /path/to/target-repo
/crawl-python /path/to/target-repo
/find-vulns-python --crawl crawl-output.json
/taint-trace --findings findings.json --crawl crawl-output.json
/validate-findings
/scan-report --findings findings.json
/generate-fix FINDING-001
```
