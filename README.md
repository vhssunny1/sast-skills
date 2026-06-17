# SAST Skills — LLM-Powered Static Analysis Pipeline

An LLM-powered SAST pipeline built entirely as Claude Code slash commands. No compiled code, no agent framework — each capability is a markdown skill that Claude executes when invoked as `/skill-name`.

Supports **Java**, **Python**, and **TypeScript/JavaScript** — including polyglot repos (e.g. Python backend + React frontend).

---

## Workflow

Run the full pipeline in one command:

```bash
/sast-full-scan /path/to/target-repo
```

Skills run sequentially. Each writes a file consumed by the next:

```
Target Repo
    │
    ▼
┌─────────────────────────────────────────────────────────────────┐
│  /detect-language                                               │
│  Counts source files, detects framework                         │
│  → language-manifest.json  (which crawl/find-vulns to run)     │
└───────────────────────────┬─────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│  /crawl-java  /crawl-python  /crawl-typescript                  │
│  Maps files by role, HTTP routes, security priority score       │
│  → crawl-output.json                                            │
└───────────────────────────┬─────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│  /config-audit                                                  │
│  Dangerous defaults in .env, docker-compose, settings files     │
│  → findings.json  (appended)                                    │
└───────────────────────────┬─────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│  /find-vulns-java  /find-vulns-python  /find-vulns-typescript   │
│  Semantic source → sink analysis — reads code, not a checklist  │
│  → findings.json  (appended)                                    │
└───────────────────────────┬─────────────────────────────────────┘
                            │
              ┌─────────────┴──────────────────┐
              │  polyglot repos only            │
              ▼                                 │
┌─────────────────────────┐                    │
│  /cross-language-taint  │                    │
│  Python backend writes  │                    │
│  → TS frontend renders  │                    │
│  → findings.json        │                    │
└────────────┬────────────┘                    │
             └─────────────┬───────────────────┘
                           ▼
┌─────────────────────────────────────────────────────────────────┐
│  /taint-trace                                                   │
│  Hop-by-hop cross-file verification — confirms or denies paths  │
│  → findings.json  (enriched: taint_path, taint_confirmed)       │
└───────────────────────────┬─────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│  /validate-findings                                             │
│  FP scoring (fp_score 0–1), deduplication, ranking             │
│  → findings.json  (enriched: validation_status)                 │
└───────────────────────────┬─────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│  /scan-report                                                   │
│  → scan-results.sarif   (SARIF 2.1.0 — IDE / GitHub Security)  │
│  → scan-summary.md      (human-readable, precision/recall)      │
└───────────────────────────┬─────────────────────────────────────┘
                            │
              ┌─────────────┴─────────────────┐
              ▼                               ▼
┌───────────────────────┐       ┌────────────────────────────┐
│  /scan-metrics        │       │  /generate-fix FINDING-001 │
│  → sast-metrics.json  │       │  → unified diff + tests    │
│  (append-only history)│       │  (on demand, per finding)  │
└───────────────────────┘       └────────────────────────────┘
```

---

## Usage

```bash
# Clone this repo
git clone https://github.com/vhssunny1/sast-skills.git
cd sast-skills

# Open Claude Code, then point at any target repo
/sast-full-scan /path/to/target-repo

# With precision/recall measurement
/sast-full-scan /path/to/target-repo --ground-truth /path/to/ground-truth.md

# Skip taint trace for a faster pass
/sast-full-scan /path/to/target-repo --skip-taint

# Run individual skills
/detect-language /path/to/target-repo
/crawl-python /path/to/target-repo
/crawl-typescript /path/to/target-repo
/config-audit /path/to/target-repo
/find-vulns-python --crawl crawl-output.json
/find-vulns-typescript --crawl crawl-output.json
/taint-trace --findings findings.json --crawl crawl-output.json
/validate-findings --findings findings.json
/scan-report --findings findings.json
/generate-fix FINDING-001
```

---

## Skills

### Orchestration

| Skill | Purpose |
|---|---|
| `detect-language` | Counts source files by extension, detects framework, writes routing manifest that tells `sast-full-scan` which crawl and find-vulns skills to run |
| `sast-full-scan` | Chains all pipeline steps in order. Writes intermediate snapshots to `sast-runs/<timestamp>/`. Options: `--ground-truth`, `--skip-taint`, `--skip-config-audit` |

### Crawl — Attack Surface Mapping

| Skill | Language | What it produces |
|---|---|---|
| `crawl` / `crawl-java` | Java | File roles, HTTP routes, Spring/Struts/JAX-RS framework detection, flagged dependencies |
| `crawl-python` | Python | File roles, Flask/FastAPI/Django routes, `async_worker` classification (Celery, RQ, Dramatiq, Huey), `security_priority` score per file, config file warnings |
| `crawl-typescript` | TypeScript / JS | File roles, React/Next.js/Express routes, `security_priority` score per file |

### Find Vulnerabilities

| Skill | Language | Vulnerability classes |
|---|---|---|
| `find-vulns` / `find-vulns-java` | Java | SQL injection, command injection, XSS, IDOR, open redirect, weak crypto, insecure deserialization, sensitive data in logs |
| `find-vulns-python` | Python | Command injection, code injection, sandbox escape, SSRF, path traversal, insecure deserialization, auth bypass, async queue taint, env-gated conditional findings |
| `find-vulns-typescript` | TypeScript / JS | DOM XSS, React XSS, mapping library popup injection, open redirect, SSRF, prototype pollution, hardcoded secrets |
| `config-audit` | Any | Dangerous feature flags, weak or default secrets, backend ports exposed past a reverse proxy, debug mode, disabled security middleware |
| `cross-language-taint` | Python + TypeScript | Stored-XSS paths where backend writes user data to DB and frontend renders it as raw HTML |

### Taint Tracing & Validation

| Skill | What it adds |
|---|---|
| `taint-trace` | Hop-by-hop taint path from entry point to sink across file boundaries. Handles async queue hops and feature-flag conditional guards. Sets `taint_confirmed`, `taint_path[]`, `conditional_protection`. |
| `validate-findings` | FP scoring rubric (`fp_score` 0.0–1.0) and `validation_status`: `confirmed` / `likely_real` / `needs_review` / `likely_fp`. Deduplicates and ranks. |

### Reporting & Fixes

| Skill | Output |
|---|---|
| `scan-report` | `scan-results.sarif` (SARIF 2.1.0) + `scan-summary.md`. Computes precision/recall when `--ground-truth` is provided. |
| `generate-fix` | Unified diff + explanation + test cases for one finding |
| `scan-metrics` | Appends run metrics to `sast-metrics.json` for trend tracking |

### Focused Hunt Skills — Standalone

Run these directly on a repo without going through the full pipeline.

| Skill | Focus |
|---|---|
| `auth-audit` | Authentication and authorization — header-based identity, missing ownership checks, insecure sessions |
| `cmd-injection` | Command injection sinks — `subprocess`, `os.system`, `Runtime.exec()`, `shell=True` |
| `ssrf-hunt` | SSRF sinks — outbound HTTP with unvalidated URLs, Git clone from user-supplied URL |
| `path-traversal` | File path construction from user input without containment guard |
| `sandbox-escape` | Restricted execution context bypasses — weakened guards in `exec()` environments |
| `frontend-hunt` | TypeScript/React client-side injection — `innerHTML`, `dangerouslySetInnerHTML`, map popups, `postMessage` |
| `waf-bypass` | Encoding and evasion patterns that bypass WAF rules |

---

## Design Principles

**Read the code, not a checklist.** Every finding is derived from tracing actual data flow in the code being scanned. No CVE lookups, no pattern tables, no prior knowledge of the target. The `evidence` field in every finding is the verbatim line from the source file.

**Security library trust model.** When a security library is used, verify the implementation honours all of its documented trust assumptions — not just that the library is imported. A library that requires specific guards or hooks provides no protection if those guards are replaced with unsafe equivalents.

**Feature-flag gated vulnerabilities are still vulnerabilities.** Code paths gated behind an env var or config flag are reported as conditional findings with a `condition` field. The flag controls when the path is exploitable, not whether the code is vulnerable.

**Taint crosses process and language boundaries.** The pipeline tracks taint across async queue hops (Celery, RQ) and across the Python→TypeScript boundary (stored data rendered as HTML). Single-language scanners miss both of these paths.

---

## Requirements

- [Claude Code](https://claude.ai/code)
- A `.git` directory at the project root — Claude Code discovers slash commands by scanning for `.claude/commands/` inside a git repo
- The skills live in this repo; the repo being scanned is a separate directory you pass as an argument
