# SAST Skills — LLM-Powered Static Analysis Pipeline

An LLM-powered SAST pipeline implemented entirely as Claude Code slash commands. No compiled code, no agent framework — each capability is a prompt-driven skill that Claude executes when invoked as `/skill-name`.

Validated against DVJA (Java/Struts2) and Redash (Python/Flask + TypeScript/React), where the pipeline discovered two previously-unreported critical vulnerabilities confirmed via DAST:
- **PY-001** — RestrictedPython sandbox escape (CVSS 9.9) in Redash's Python query runner
- **PY-004** — Authentication bypass via unsigned `X-Forwarded-Remote-User` header (CVSS 9.8)

---

## Architecture

Skills run sequentially; each writes a file consumed by the next.

```
detect-language  → language-manifest.json
crawl-{lang}     → crawl-output.json        (classifies files by role + security_priority)
config-audit     → findings.json            (dangerous defaults in .env, docker-compose)
find-vulns-{lang}→ findings.json            (semantic source→sink reasoning)
cross-lang-taint → findings.json            (Python store → TypeScript render XSS, polyglot only)
taint-trace      → findings.json            (cross-file path verification)
validate-findings→ findings.json            (FP scoring + ranking)
scan-report      → scan-results.sarif
                   scan-summary.md
scan-metrics     → sast-metrics.json        (append-only history)
generate-fix     → diff + explanation       (per finding, on demand)
```

### Why skills, not a Python agent?

Each skill runs independently in CI or on-demand. You can `/crawl` a repo once, then iterate on `/find-vulns` without re-crawling. Individual skills can be invoked, improved, and tested in isolation. See `Architecture-Comparison.MD` for the full tradeoff analysis.

---

## Quick Start

```bash
# Full pipeline — auto-detects language, measures precision/recall
/sast-full-scan dvja --ground-truth dvja-ground-truth.MD

# Polyglot repo (Python backend + React frontend)
/sast-full-scan redash

# Individual skills
/detect-language my-repo
/crawl-python my-repo
/config-audit my-repo
/find-vulns-python --crawl crawl-output.json
/cross-language-taint --findings findings.json --crawl crawl-output.json
/taint-trace --findings findings.json --crawl crawl-output.json
/validate-findings --findings findings.json
/scan-report --findings findings.json --ground-truth dvja-ground-truth.MD
/generate-fix FINDING-001
/scan-metrics --run-dir sast-runs/<timestamp>/
```

---

## Skills Reference

### Orchestration

| Skill | Invocation | Purpose |
|---|---|---|
| `detect-language` | `/detect-language <repo>` | Counts files by extension, detects framework, writes `language-manifest.json` routing to correct crawl/find-vulns skills |
| `sast-full-scan` | `/sast-full-scan <repo>` | Chains all steps. Supports `--ground-truth`, `--skip-taint`, `--skip-config-audit` |

### Crawl (attack surface mapping)

| Skill | Languages | Key output |
|---|---|---|
| `crawl` / `crawl-java` | Java | Entry points, routes, roles, Spring/Struts detection |
| `crawl-python` | Python | Flask/FastAPI/Django routes; `async_worker` role for Celery/RQ/Dramatiq/Huey; `security_priority` (1–5) per file; `config_warnings[]` for dangerous .env defaults |
| `crawl-typescript` | TypeScript/JS | React/Next.js/Express routes; `security_priority` per file |

### Vulnerability Detection

| Skill | Language | Notable sinks |
|---|---|---|
| `find-vulns` / `find-vulns-java` | Java | SQL injection, command injection, XSS in JSP, IDOR, insecure crypto |
| `find-vulns-python` | Python | Command injection, code injection, **sandbox escape** (RestrictedPython `_getattr_` guard), SSRF, path traversal, **feature-flag gated auth bypass**, async queue taint |
| `find-vulns-typescript` | TypeScript/JS | DOM XSS, `dangerouslySetInnerHTML`, **Leaflet/Mapbox popup HTML injection**, open redirect, prototype pollution, SSRF |
| `config-audit` | Any | Dangerous defaults in `.env` / `docker-compose` / `settings.py` — feature flags, weak secrets, backend port exposure, debug mode |
| `cross-language-taint` | Python + TS | Stored-XSS paths where Python backend stores user data → TypeScript renders it via `bindPopup()` or `innerHTML` without sanitization |

### Analysis & Reporting

| Skill | Purpose |
|---|---|
| `taint-trace` | Cross-file path verification. Adds `taint_path[]`, `taint_confirmed`, `conditional_protection`. Handles async queue hops (RQ/Celery) and feature-flag gated paths. |
| `validate-findings` | FP scoring rubric. Assigns `fp_score` and `validation_status` (`confirmed` / `likely_real` / `needs_review` / `likely_fp`). |
| `scan-report` | SARIF 2.1.0 (`scan-results.sarif`) + Markdown (`scan-summary.md`). Precision/recall when `--ground-truth` provided. |
| `generate-fix` | Per-finding unified diff + explanation + test cases. |
| `scan-metrics` | Appends run metrics to `sast-metrics.json` for trend tracking. |

### Focused Hunt Skills (standalone)

| Skill | Purpose |
|---|---|
| `auth-audit` | Authentication and authorization checks across a repo |
| `cmd-injection` | Deep scan for command injection patterns |
| `ssrf-hunt` | Server-side request forgery sinks |
| `path-traversal` | File path construction from user input |
| `sandbox-escape` | Restricted execution context bypass patterns |
| `frontend-hunt` | TypeScript/React XSS and client-side injection |
| `waf-bypass` | Patterns that evade WAF rules |

---

## Key Design Principles

### No pattern-matching against known CVEs

`find-vulns-*` skills derive findings by reading code and reasoning about data flow (source → sink). They never consult CVE databases, ground truth files, or prior knowledge of the target repo. This is enforced as a hard constraint in every skill.

### Security library trust model

When a security library is present (RestrictedPython, `advocate`, `bleach`, etc.), the skill checks whether the implementation honours **all** of the library's documented trust assumptions — not just whether the library is imported.

Example: RestrictedPython requires `_getattr_ = safe_getattr`. Redash set `_getattr_ = getattr` (real builtin), nullifying the sandbox. The skill detects this by reading the guard installation code, not by pattern-matching on library name.

### Feature-flag gated vulnerabilities

Some code paths are only exploitable when an environment variable is set (e.g. `REMOTE_USER_LOGIN_ENABLED=true`). These are reported as conditional findings with a `condition` field. They are real vulnerabilities — the flag scopes *when* they are exploitable, not *whether* the code is vulnerable.

### Taint crosses process and language boundaries

- **Async queue:** `entry_point → queue.enqueue(tainted) → async_worker → sink` is a valid taint path across a Redis/RabbitMQ boundary. `taint-trace` represents the broker hop as `role: "async_queue"`.
- **Cross-language:** Python backend stores data → TypeScript frontend renders it in Leaflet popup → stored XSS. `cross-language-taint` matches these paths across the language boundary.

---

## Validated Results

### Redash (Python/Flask + TypeScript/React)

| Finding | CWE | CVSS | DAST Confirmed |
|---|---|---|---|
| PY-001 RestrictedPython sandbox escape | CWE-94 | 9.9 Critical | ✅ `uid=1000(redash)` |
| PY-002 OS command injection (Script runner) | CWE-78 | 9.1 Critical | ✅ `uid=1000(redash)` |
| PY-003 SSRF (url_for parameter) | CWE-918 | 7.5 High | advocate library present — mitigated |
| PY-004 Remote user auth bypass | CWE-287 | 9.8 Critical | ✅ Full admin session, zero credentials |
| PY-005 Sensitive data in logs | CWE-532 | 4.3 Medium | — |
| TS-001 Leaflet popup stored XSS | CWE-79 | 6.1 Medium | — |

Disclosure reports: [`disclosure/`](disclosure/)

### DVJA (Java/Struts2) — ground truth baseline

Target: 10 statically-detectable vulnerabilities (GT-01 through GT-10 in `dvja-ground-truth.MD`). Recall target ≥ 0.8 before Milestone 3.

---

## File Structure

```
.claude/commands/        ← all skill files (must be flat — subdirs not recognized)
disclosure/              ← responsible disclosure reports (GHSA format)
dvja/                    ← DVJA Java test target
redash/                  ← Redash Python/TS assessment target
dvja-ground-truth.MD     ← 12 known DVJA vulnerabilities for precision/recall
crawl-output.json        ← last crawl run output
findings.json            ← live findings (enriched progressively)
scan-results.sarif       ← last scan SARIF output
scan-summary.md          ← last scan Markdown report
sast-metrics.json        ← append-only metrics history
redash-assessment-report.md ← full Redash assessment
CLAUDE.md                ← project instructions for Claude Code
Steps.MD                 ← milestone plan
```

---

## Requirements

- Claude Code CLI (claude.ai/code)
- A git repository at the project root (Claude Code needs `.git` to discover project-level slash commands)
- Nested repos (dvja, redash) have their own `.git` — the outer SAST directory also needs one

---

## Responsible Disclosure

Vulnerabilities found by this pipeline in open-source software should be reported to maintainers privately before public disclosure. The reports in `disclosure/` follow GitHub Security Advisory format with a standard 90-day disclosure window.

Findings must be derived from source code review only. Testing against systems you do not own or operate is unauthorized access regardless of intent.
