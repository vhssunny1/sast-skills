# SAST Skills — LLM-Powered Static Analysis Pipeline

An LLM-powered SAST pipeline built entirely as Claude Code slash commands. No compiled code, no agent framework — each capability is a markdown skill that Claude executes when invoked as `/skill-name`.

Supports **Java**, **Python**, and **TypeScript/JavaScript** — including polyglot repos (e.g. Python backend + React frontend).

---

## Workflow

Run the full pipeline in one command:

```bash
/sast-full-scan /path/to/target-repo
```

Independent steps run concurrently; dependent steps run sequentially. Each step writes a file consumed by the next:

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
          ┌─────────────────▼──────────────────────────────────────┐
          │  GROUP 1 — concurrent (no cross-dependencies)           │
          │                                                         │
          │  /crawl-python  /crawl-typescript  /crawl-java          │
          │  Maps files by role, HTTP routes, security priority     │
          │  → crawl-output-<lang>.json  (merged after group)       │
          │                                                         │
          │  /config-audit                                          │
          │  Secrets, flags, supply chain in .env/.cfg/Dockerfile   │
          │  → findings.json  (appended)                            │
          └────────────────────────────┬────────────────────────────┘
                   merge crawl outputs │
                                       ▼
          ┌────────────────────────────────────────────────────────┐
          │  GROUP 2 — concurrent (both read merged crawl output)  │
          │                                                        │
          │  /find-vulns-python  /find-vulns-typescript            │
          │  /find-vulns-java                                      │
          │  Semantic source → sink analysis + CVSS 3.1 scoring    │
          │  → findings-<lang>.json  (merged after group)          │
          └────────────────────────┬───────────────────────────────┘
                merge all findings │
                                   ▼
┌─────────────────────────────────────────────────────────────────┐
│  GROUP 3 — sequential                                           │
└─────────────────────────────────────────────────────────────────┘
                            │
              ┌─────────────┴──────────────────┐
              │  polyglot repos only            │
              ▼                                 │
┌─────────────────────────┐                    │
│  /cross-language-taint  │                    │
│  Stored-XSS across lang │                    │
│  + RAG prompt injection │                    │
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
│  FP scoring (fp_score 0–1), deduplication                       │
│  Rank by: severity → cvss_score DESC → fp_score ASC            │
│  → findings.json  (enriched: validation_status, fp_score)       │
└───────────────────────────┬─────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│  /scan-report                                                   │
│  → scan-results.sarif   (SARIF 2.1.0 + CVSS per finding)       │
│  → scan-summary.md      (human-readable, CVSS range, P/R)       │
└───────────────────────────┬─────────────────────────────────────┘
                            │
              ┌─────────────┴─────────────────┐
              ▼                               ▼
┌───────────────────────┐       ┌────────────────────────────┐
│  /scan-metrics        │       │  /generate-fix FINDING-001 │
│  → sast-metrics.json  │       │  → unified diff + tests    │
│  + step_timings from  │       │  (on demand, per finding)  │
│    run-log.json        │       │                            │
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

# Custom output directory
/sast-full-scan /path/to/target-repo --out-dir ./reports/sprint-42/

# Skip config-audit (use when no .env or docker-compose present)
/sast-full-scan /path/to/target-repo --skip-config-audit

# Generate a DAST test script from confirmed findings (run after the app is live)
/sast-full-scan /path/to/target-repo --dast

# Run individual skills
/detect-language /path/to/target-repo
/crawl-python /path/to/target-repo
/crawl-typescript /path/to/target-repo
/config-audit /path/to/target-repo
/find-vulns-python --crawl crawl-output.json
/find-vulns-typescript --crawl crawl-output.json
/find-vulns-java --crawl crawl-output.json
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
| `sast-full-scan` | Orchestrates the pipeline in three execution groups: **Group 1** (crawl + config-audit, concurrent) → **Group 2** (find-vulns, concurrent) → **Group 3** (cross-lang-taint → taint-trace → validate → report, sequential). Writes intermediate snapshots to `sast-runs/<timestamp>/` including a structured `run-log.json` per step. Options: `--ground-truth`, `--skip-taint`, `--skip-config-audit`, `--out-dir`, `--dast` |

### Crawl — Attack Surface Mapping

| Skill | Language | What it produces |
|---|---|---|
| `crawl` / `crawl-java` | Java | File roles, HTTP routes, Spring/Struts/JAX-RS framework detection, flagged dependencies |
| `crawl-python` | Python | File roles, Flask/FastAPI/Django routes, `async_worker` classification (Celery, RQ, Dramatiq, Huey), `security_priority` score per file, config file warnings |
| `crawl-typescript` | TypeScript / JS | File roles, React/Next.js/Express routes, `security_priority` score per file |

### Find Vulnerabilities

| Skill | Language | Vulnerability classes |
|---|---|---|
| `find-vulns` / `find-vulns-java` | Java | SQL/JPQL injection, command injection, XSS, IDOR (missing ownership check), open redirect, weak crypto, insecure deserialization, outbound leakage, resource exhaustion/ReDoS, dead defensive code. Each finding includes `cvss_vector` + `cvss_score`. |
| `find-vulns-python` | Python | Command injection, code injection, sandbox escape, SSRF, path traversal (Zip Slip, symlink, glob, output_dir), IDOR, YAML/CSV/Cypher/LogQL injection, insecure deserialization, auth bypass, async queue taint, outbound leakage, dead defensive code, resource exhaustion/ReDoS, application-code supply chain (download+execute without hash), falsy size guard bypass, env-gated conditional findings. Each finding includes `cvss_vector` + `cvss_score`. |
| `find-vulns-typescript` | TypeScript / JS | DOM XSS, React XSS, mapping library popup injection, CSS-as-HTML injection, open redirect, SSRF, session cookie exfiltration, IDOR (Node/Express ownership checks), prototype pollution, hardcoded secrets, outbound leakage, dead defensive code, resource exhaustion/ReDoS. Each finding includes `cvss_vector` + `cvss_score`. |
| `config-audit` | Any | Dangerous feature flags, weak/default secrets in `.env`/`.cfg`/`.ini`/`.conf`/`constants.py`, OIDC nonce disabled, CORS wildcard+credentials, mock auth bypass, Dockerfile supply chain (curl\|bash, unpinned git clone, binary wheels, FROM without digest), CI pipeline injection, backend ports exposed past reverse proxy. Each finding includes `cvss_vector` + `cvss_score`. |
| `cross-language-taint` | Python + TypeScript | Stored-XSS paths where Python backend writes user data and TypeScript frontend renders as raw HTML; multi-hop prompt injection via RAG retrieval pipeline |

### Taint Tracing & Validation

| Skill | What it adds |
|---|---|
| `taint-trace` | Hop-by-hop taint path from entry point to sink across file boundaries. Handles async queue hops and feature-flag conditional guards. Sets `taint_confirmed`, `taint_path[]`, `conditional_protection`. |
| `validate-findings` | FP scoring rubric (`fp_score` 0.0–1.0) and `validation_status`: `confirmed` / `likely_real` / `needs_review` / `likely_fp`. Deduplicates. Ranks by severity → `cvss_score` DESC → `fp_score` ASC. |

### Reporting & Fixes

| Skill | Output |
|---|---|
| `scan-report` | `scan-results.sarif` (SARIF 2.1.0, includes `cvss_vector` + `cvss_score` per result) + `scan-summary.md` (CVSS range in summary, per-finding CVSS row). Computes precision/recall when `--ground-truth` is provided. |
| `generate-fix` | Unified diff + explanation + test cases for one finding |
| `scan-metrics` | Appends run metrics to `sast-metrics.json`. Reads `run-log.json` to extract `step_timings[]` — per-step duration, findings delta, and error capture for trend analysis and scan debugging. |

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

## Recent Changes

| Feature | What changed |
|---|---|
| **CVSS 3.1 numeric scoring** | All `find-vulns-*` and `config-audit` skills now output `cvss_vector` (e.g. `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`) and `cvss_score` (float). Each skill includes a reference table of pre-computed vectors for ~20 common vulnerability classes. `validate-findings` sorts within severity bands by `cvss_score` DESC. `scan-report` emits both fields in SARIF and Markdown. |
| **Structured scan run logs** | `sast-full-scan` now writes `run-log.json` per run — one entry per pipeline step with start time, end time, findings delta, step-specific notes, and error capture. `scan-metrics` reads it to populate `step_timings[]` in `sast-metrics.json`, enabling per-step duration tracking and cross-run trend analysis. |
| **Parallel skill execution** | `sast-full-scan` now runs in three groups: Group 1 (crawl + config-audit concurrently), Group 2 (all find-vulns concurrently after crawl merge), Group 3 (sequential). ~30–40% wall-clock reduction for polyglot repos. |

---

## Design Principles

**Read the code, not a checklist.** Every finding is derived from tracing actual data flow in the code being scanned. No CVE lookups, no pattern tables, no prior knowledge of the target. The `evidence` field in every finding is the verbatim line from the source file.

**Security library trust model.** When a security library is used, verify the implementation honours all of its documented trust assumptions — not just that the library is imported. A library that requires specific guards or hooks provides no protection if those guards are replaced with unsafe equivalents.

**Feature-flag gated vulnerabilities are still vulnerabilities.** Code paths gated behind an env var or config flag are reported as conditional findings with a `condition` field. The flag controls when the path is exploitable, not whether the code is vulnerable.

**Taint crosses process and language boundaries.** The pipeline tracks taint across async queue hops (Celery, RQ) and across the Python→TypeScript boundary (stored data rendered as HTML). Single-language scanners miss both of these paths.

**Absence-based detection alongside presence-based taint.** IDOR (missing ownership check) is detected by asking "is the resource owner compared against the caller?" — not by tracing a dangerous data flow. This pattern is embedded into Q2 of each language skill so it runs on every handler without a separate pipeline stage.

**Supply chain is a first-class concern.** config-audit scans Dockerfiles, CI pipeline files, and reverse-proxy config files (`.cfg`, `.ini`) in addition to runtime environment files. find-vulns-python checks application code that downloads and executes external binaries without hash verification.

---

## Requirements

- [Claude Code](https://claude.ai/code)
- A `.git` directory at the project root — Claude Code discovers slash commands by scanning for `.claude/commands/` inside a git repo
- The skills live in this repo; the repo being scanned is a separate directory you pass as an argument
