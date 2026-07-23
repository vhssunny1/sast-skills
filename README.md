# SAST Skills — LLM-Powered Static Analysis Pipeline

An LLM-powered SAST pipeline built entirely as Claude Code slash commands. No compiled code, no agent framework — each capability is a markdown skill that Claude executes when invoked as `/skill-name`.

Supports **Java**, **Python**, and **TypeScript/JavaScript** — including polyglot repos (e.g. Python backend + React frontend).

The pipeline integrates optional **graph-based analysis** (Joern CPG pre-analysis, CodeQL second-signal) alongside the LLM semantic engine so that neither coverage completeness nor semantic accuracy is sacrificed.

---

## Workflow

Run the full pipeline in one command:

```bash
/sast-full-scan /path/to/target-repo
```

With graph tools (strongly recommended for large repos):

```bash
# Joern runs automatically if installed. Add CodeQL second-signal:
/sast-full-scan /path/to/target-repo --codeql
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
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│  /crawl-tree-sitter  [auto — falls back to LLM crawl if missing]│
│  Fast mechanical AST pre-scan (tree-sitter CLI) — functions,     │
│  routes, imports, dangerous patterns — before the LLM crawl.     │
│  → crawl-output.json  (ts_available: true, if it ran)           │
└───────────────────────────┬─────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│  /joern-parse    [auto — skipped gracefully if Joern missing]   │
│  Builds Code Property Graph (CPG) — exhaustive taint paths,     │
│  call graph, unreachable sinks. find-vulns uses this to guide   │
│  file prioritization and confirm taint chains faster.           │
│  → cpg-output.json  (taint_paths[], call_graph[], unreachable)  │
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
          │  GROUP 2 — find-vulns run sequentially per language,   │
          │  /codeql-scan runs concurrently alongside that chain   │
          │                                                        │
          │  /find-vulns-python  /find-vulns-typescript            │
          │  /find-vulns-java                                      │
          │  Step 1.5: load CPG hints → boost priority on CPG-hit  │
          │  files → confirm CPG candidates via LLM read →         │
          │  then run full LLM discovery for paths CPG missed.     │
          │  Each language's priority≥2 file list is split into    │
          │  fixed-size batches (one skill call per batch) so      │
          │  coverage is guaranteed rather than self-paced by a    │
          │  single agent turn — every required file gets read.    │
          │  → findings.json  (CONFIG-* findings explicitly        │
          │    preserved across the merge, not overwritten)        │
          │                                                        │
          │  /codeql-scan     [optional — --codeql flag]           │
          │  Runs CodeQL in parallel. Confirms LLM findings and    │
          │  surfaces paths both Joern+LLM missed.                 │
          │  → codeql-output.json  (merged into findings)          │
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
│  Uses call_graph[] from cpg-output.json for caller lookup       │
│  → findings.json  (enriched: taint_path, taint_confirmed)       │
└───────────────────────────┬─────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│  /validate-findings                                             │
│  FP scoring (fp_score 0–1), deduplication                       │
│  -0.25 fp_score bonus for codeql_confirmed findings             │
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
# Standard scan — Joern runs automatically if installed
/sast-full-scan /path/to/target-repo

# With CodeQL second-signal confirmation (requires CodeQL CLI)
/sast-full-scan /path/to/target-repo --codeql

# With precision/recall measurement against a known-bugs list
/sast-full-scan /path/to/target-repo --ground-truth /path/to/ground-truth.md

# Skip Joern (faster pass, no graph coverage guarantee)
/sast-full-scan /path/to/target-repo --skip-joern

# Skip taint trace (even faster, higher FP rate)
/sast-full-scan /path/to/target-repo --skip-taint

# Generate a DAST test script from confirmed findings
/sast-full-scan /path/to/target-repo --dast

# Full options combined
/sast-full-scan /path/to/target-repo --codeql --ground-truth gt.md --dast

# Custom output directory
/sast-full-scan /path/to/target-repo --out-dir ./reports/sprint-42/

# Skip config-audit (use when no .env or docker-compose present)
/sast-full-scan /path/to/target-repo --skip-config-audit

# Resume an interrupted scan (auto-detected, or specify run ID)
/sast-full-scan /path/to/target-repo               # auto-resumes if prior run failed
/sast-full-scan /path/to/target-repo --fresh        # force fresh scan
/sast-full-scan /path/to/target-repo --resume 20260722-143656

# Run individual skills
/detect-language /path/to/target-repo
/joern-parse /path/to/target-repo --manifest language-manifest.json
/crawl-python /path/to/target-repo
/crawl-typescript /path/to/target-repo
/config-audit /path/to/target-repo
/find-vulns-python --crawl crawl-output.json
/find-vulns-typescript --crawl crawl-output.json
/find-vulns-java --crawl crawl-output.json
/codeql-scan /path/to/target-repo --manifest language-manifest.json
/taint-trace --findings findings.json --crawl crawl-output.json
/validate-findings --findings findings.json
/scan-report --findings findings.json
/generate-fix FINDING-001
```

---

## Installing Graph Tools (Optional but Recommended)

### Joern — CPG pre-analysis

Joern provides exhaustive graph-based taint path discovery. The pipeline detects it automatically.

```bash
# macOS / Linux
curl -L "https://github.com/joernio/joern/releases/latest/download/joern-install.sh" | bash

# Verify
joern --version
```

Once installed, every `/sast-full-scan` run automatically builds a CPG before crawl. Pass `--skip-joern` to bypass.

**What Joern adds:** Every graph-reachable taint path is mapped before the LLM begins analysis. find-vulns skills prioritize CPG-hit files first and pre-confirm chains the graph already traced — so second-order (stored-then-rendered) flows, deep multi-hop chains, and all-callers-of-a-sink are found even if the LLM would have missed them reading one file at a time.

### CodeQL — Second-signal confirmation

CodeQL independently runs inter-procedural dataflow analysis and cross-references its results against LLM findings.

```bash
# Download CodeQL CLI
# https://github.com/github/codeql-cli-binaries/releases

# Install query packs
gh extensions install github/gh-codeql
codeql pack download codeql/javascript-queries codeql/python-queries codeql/java-queries

# Verify
codeql version
```

Pass `--codeql` to activate. CodeQL runs in parallel with find-vulns so it adds minimal wall time.

**What CodeQL adds:** LLM findings confirmed by CodeQL get their false-positive score reduced by 0.25. Paths CodeQL found that the LLM missed are added as `CQL-*` findings and traced by taint-trace.

---

## Skills

### Graph Analysis (New)

| Skill | Purpose |
|---|---|
| `joern-parse` | Builds a Code Property Graph via Joern. Exports `cpg-output.json` with all graph-reachable taint paths, call graph edges, and unreachable sinks. Auto-runs if Joern installed; graceful skip otherwise. |
| `codeql-scan` | Runs CodeQL security queries and cross-references against LLM findings. Confirms existing findings (lowers fp_score) and adds `CQL-*` findings for paths the LLM missed. Optional — `--codeql` flag. |

### Orchestration

| Skill | Purpose |
|---|---|
| `detect-language` | Counts source files by extension, detects framework, writes routing manifest |
| `sast-full-scan` | Orchestrates the full pipeline: detect → **crawl-tree-sitter** → **joern-parse** → Group 1 (crawl + config-audit) → Group 2 (find-vulns, batched per language + **codeql-scan**) → Group 3 (taint-trace → validate → report). Options: `--codeql`, `--skip-joern`, `--skip-tree-sitter`, `--ground-truth`, `--skip-taint`, `--skip-config-audit`, `--out-dir`, `--dast`, `--fresh`, `--resume` |

### Crawl — Attack Surface Mapping

| Skill | Language | What it produces |
|---|---|---|
| `crawl-tree-sitter` | Java / Python / TypeScript / JS | Fast mechanical AST pre-scan via the tree-sitter CLI — functions, routes, imports, dangerous patterns — run before the LLM crawl. Falls back gracefully (`ts_available: false`) if the CLI or a language grammar isn't installed. |
| `crawl` / `crawl-java` | Java | File roles, HTTP routes, Spring/Struts/JAX-RS framework detection, `security_priority` score per file (1–5 rubric: deserialization/OGNL/`Runtime.exec` at 5 down to pure POJOs at 1), flagged dependencies |
| `crawl-python` | Python | File roles, Flask/FastAPI/Django routes, `async_worker` classification (Celery, RQ, Dramatiq, Huey), `security_priority` score per file |
| `crawl-typescript` | TypeScript / JS | File roles, React/Next.js/Express routes, `security_priority` score per file (1–5 rubric: `dangerouslySetInnerHTML`/`eval`/shell exec at 5 down to pure types/constants at 1) |

All three crawl skills now share the same `security_priority` (1–5) scoring discipline — every file the crawl assigns priority ≥ 2 is contractually guaranteed a full read pass in the matching `find-vulns-*` skill; only priority-1 files (pure data/type definitions, generated code) may be skipped.

### Find Vulnerabilities

All find-vulns skills now include **Step 1.5** — CPG taint hint loading. If `cpg-output.json` is present, files with CPG-confirmed taint paths are boosted in priority and their paths are pre-confirmed, reducing redundant file reads.

| Skill | Language | Vulnerability classes |
|---|---|---|
| `find-vulns` / `find-vulns-java` | Java | SQL/JPQL injection, command injection, XSS, IDOR, open redirect, weak crypto, insecure deserialization, outbound leakage, resource exhaustion/ReDoS, dead defensive code. CVSS 3.1 per finding. |
| `find-vulns-python` | Python | Command injection, code injection, sandbox escape, SSRF, path traversal (Zip Slip, symlink, glob), IDOR, YAML/CSV/Cypher/LogQL injection, insecure deserialization, auth bypass, async queue taint, outbound leakage, dead defensive code, resource exhaustion/ReDoS. CVSS 3.1 per finding. |
| `find-vulns-typescript` | TypeScript / JS | DOM XSS, React XSS, mapping library popup injection, CSS-as-HTML injection, open redirect, SSRF, session cookie exfiltration, IDOR (Node/Express ownership checks), prototype pollution, hardcoded secrets, outbound leakage, dead defensive code, resource exhaustion/ReDoS. CVSS 3.1 per finding. |
| `config-audit` | Any | Dangerous feature flags, weak/default secrets in `.env`/`.cfg`/`.ini`, OIDC nonce disabled, CORS wildcard+credentials, mock auth bypass, Dockerfile supply chain (curl\|bash, unpinned FROM, binary wheels), CI pipeline injection. CVSS 3.1 per finding. |
| `cross-language-taint` | Python + TypeScript | Stored-XSS paths where Python writes user data and TypeScript renders it; multi-hop prompt injection via RAG retrieval |

### Taint Tracing & Validation

| Skill | What it adds |
|---|---|
| `taint-trace` | Hop-by-hop taint path across file boundaries. Uses `call_graph[]` from CPG for caller lookup without extra file reads. Sets `taint_confirmed`, `taint_path[]`, `conditional_protection`. |
| `validate-findings` | FP scoring (`fp_score` 0.0–1.0) and `validation_status`. Applies −0.25 for `codeql_confirmed` findings. Deduplicates. Ranks by severity → `cvss_score` DESC → `fp_score` ASC. |

### Reporting & Fixes

| Skill | Output |
|---|---|
| `scan-report` | `scan-results.sarif` (SARIF 2.1.0 with `cvss_vector`, `cvss_score`, `cpg_guided`, `codeql_confirmed` per result) + `scan-summary.md`. Computes precision/recall when `--ground-truth` is provided. |
| `generate-fix` | Unified diff + explanation + test cases for one finding |
| `scan-metrics` | Appends run metrics to `sast-metrics.json`. Reads `run-log.json` for `step_timings[]` — per-step duration, findings delta, error capture. |

---

## Finding ID Prefixes

| Prefix | Source skill | Meaning |
|---|---|---|
| `CONFIG-*` | `/config-audit` | Configuration / deployment finding |
| `PY-*` | `/find-vulns-python` | Python source finding |
| `TS-*` | `/find-vulns-typescript` | TypeScript/React source finding |
| `JAVA-*` | `/find-vulns-java` | Java source finding |
| `XL-*` | `/cross-language-taint` | Cross-language taint path |
| `CQL-*` | `/codeql-scan` | CodeQL-only finding (no LLM match; traced by taint-trace) |

---

## Output Artifacts

Every full scan writes to `sast-runs/<timestamp>/`:

| File | Contents |
|---|---|
| `language-manifest.json` | Detected languages, frameworks, pipeline routing |
| `cpg-output.json` | Joern CPG: taint paths, call graph, unreachable sinks |
| `crawl-output.json` | File map, roles, routes (merged for polyglot) |
| `findings-after-config-audit.json` | Config findings snapshot |
| `codeql-output.json` | CodeQL confirmation results (only when `--codeql`) |
| `findings-raw.json` | Candidates from find-vulns + codeql-scan |
| `findings-traced.json` | After taint-trace enrichment |
| `findings-validated.json` | After fp_score scoring and ranking |
| `findings-final.json` | Final enriched findings |
| `scan-results.sarif` | SARIF 2.1.0 for IDE/GitHub Security tab |
| `scan-summary.md` | Human-readable report with fixes and CVSS |
| `run-log.json` | Per-step timing, findings delta, errors |
| `run-manifest.json` | Run metadata (repo, timestamps, status) |
| `dast-tests.py` | DAST test script (only when `--dast`) |

---

## Recent Changes

| Feature | What changed |
|---|---|
| **Joern CPG pre-analysis** | `/joern-parse` runs automatically before Group 1 if Joern is installed. Exports all graph-reachable taint paths to `cpg-output.json`. find-vulns skills load this in Step 1.5 to boost file priorities, pre-confirm taint candidates, and use the call graph for caller resolution — catching second-order flows and deep chains the LLM alone would miss. |
| **CodeQL second-signal** | Optional `/codeql-scan` runs in Group 2 (parallel with find-vulns, no wall-time cost). Confirms LLM findings (−0.25 fp_score) and surfaces `CQL-*` findings for paths both Joern and LLM missed. Activate with `--codeql`. |
| **Graph-guided find-vulns** | All three find-vulns skills (TypeScript, Python, Java) now include Step 1.5: CPG taint hint loading, file priority boosting, CPG candidate pre-population, and Step 4b CPG candidate confirmation. Findings track `cpg_guided` and `llm_discovered` counts. |
| **tree-sitter fast pre-crawl** | `/crawl-tree-sitter` runs before Group 1 (auto-detected). Mechanical AST scan is faster than an LLM crawl and supersedes it when available; falls back gracefully to the standard `crawl-*` skills otherwise. |
| **Coverage-completeness batching** | `find-vulns-*` now splits each language's `security_priority ≥ 2` file list into fixed-size batches (40 files) and invokes the skill once per batch. Fixes a real regression where a single agent turn asked to exhaustively read 200+ files was self-truncating (observed: 27/232 required files actually read in one run) — every required file is now guaranteed a read pass. |
| **CONFIG findings no longer lost** | `find-vulns-*` skills hardcode "overwrite `findings.json`" in their own instructions, which was silently deleting all `config-audit` findings on every scan. The harness now explicitly preserves and re-merges `CONFIG-*` findings after find-vulns runs, for both single-language and polyglot repos (the previous polyglot merge path was also broken — it read a filename the skills never actually wrote). |
| **Consistent `security_priority` rubric across languages** | `crawl-typescript` and `crawl-java` previously had no documented scoring rubric (unlike Python) — the model was improvising priority scores with no repeatable criteria. Both now have an explicit 1–5 table aligned to their `find-vulns-*` sink patterns, matching Python's format. |
| **Web harness accepts local paths** | `harness/harness.py` now resolves local folder paths in addition to GitHub URLs. Pass `/path/to/local-repo` or `https://github.com/...` interchangeably. |
| **SKILL_TIMEOUT extended** | `harness/agent.py` raises `SKILL_TIMEOUT` to 7200s (2 hours) to accommodate large repos (400+ file TypeScript scans that previously timed out). |
| **Scan cancel/delete actually stop the pipeline** | Previously "Cancel"/"Delete" in the web UI only detached the SSE stream — the background pipeline task (and its in-flight `claude` subprocess) kept running invisibly. Both now properly cancel the task and kill the subprocess. A history item can also be permanently deleted (new trash icon per scan, plus a "Clear all" control), separate from cancelling an active run. |
| **Per-step timing + findings metrics in the UI** | Each pipeline step now reports its own duration and findings delta, shown live as the scan runs and when reviewing scan history — not just a final total. |
| **CVSS 3.1 numeric scoring** | All `find-vulns-*` and `config-audit` skills output `cvss_vector` and `cvss_score` per finding. `validate-findings` sorts within severity bands by `cvss_score` DESC. `scan-report` emits both fields in SARIF and Markdown. |
| **Structured scan run logs** | `sast-full-scan` writes `run-log.json` per run — one entry per pipeline step with timing, findings delta, and error capture. `scan-metrics` reads it for per-step trend analysis. |
| **Parallel skill execution** | Group 1 (crawl + config-audit) runs concurrently. In Group 2, `find-vulns-*` now runs sequentially per language (required — they share one output file), while `codeql-scan` runs concurrently alongside that chain. |

---

## Why Graph Tools + LLM

Traditional SAST tools use one approach or the other:

| Approach | Strength | Gap |
|---|---|---|
| Graph-only (Joern, CodeQL) | Exhaustive — every reachable path found | Cannot judge whether a sanitizer is semantically effective |
| LLM-only (prior pipeline) | Reads actual semantics — catches subtle bypasses | Misses paths requiring 5+ file hops; no call-graph completeness |
| **This pipeline** | **Both** — graph for coverage, LLM for confirmation | Best of both; adds graph tool install requirement |

The key insight: Joern guarantees **recall** (no missed paths). The LLM guarantees **precision** (no false positives from syntactically-present-but-semantically-inactive sanitizers). CodeQL provides an independent third check for findings where both matter.

---

## Design Principles

**Read the code, not a checklist.** Every finding is derived from tracing actual data flow in the code being scanned. CPG taint hints guide which files to read first — the LLM still reads every confirmed file. The `evidence` field is always the verbatim line from source.

**Graph completeness + LLM semantics.** Joern finds every path the call graph can reach. The LLM reads the code to confirm whether a sanitizer in that path is genuinely effective. Neither alone is sufficient.

**Graceful degradation.** Joern and CodeQL are optional. If neither is installed, the pipeline runs in LLM-only mode (existing behavior). If only Joern is installed, CPG hints improve coverage. If both are installed, findings have three-layer confirmation.

**Taint crosses process and language boundaries.** The pipeline tracks taint across async queue hops (Celery, RQ) and across the Python→TypeScript boundary (stored data rendered as HTML). Single-language scanners miss both.

**Absence-based detection alongside taint.** IDOR is detected by asking "is the resource owner compared against the caller?" — not by tracing a dangerous data flow. This runs on every handler in every language skill.

**Supply chain is a first-class concern.** config-audit scans Dockerfiles, CI pipeline files, and reverse-proxy config files. find-vulns-python checks application code that downloads and executes external binaries without hash verification.

---

## Requirements

- [Claude Code](https://claude.ai/code)
- A `.git` directory at the project root — Claude Code discovers slash commands by scanning for `.claude/commands/` inside a git repo
- The skills live in this repo; the repo being scanned is a separate directory passed as an argument
- **Optional:** [Joern](https://docs.joern.io/installation) — for CPG pre-analysis (auto-detected)
- **Optional:** [CodeQL CLI](https://github.com/github/codeql-cli-binaries/releases) — for second-signal confirmation (`--codeql` flag)
- **Optional:** [tree-sitter CLI](https://github.com/tree-sitter/tree-sitter/blob/master/cli/README.md) — for the fast mechanical pre-crawl (auto-detected). On Windows, grammar compilation requires a C compiler with Windows SDK headers (e.g. Visual Studio Build Tools) — without one, tree-sitter falls back gracefully to the standard LLM crawl.
