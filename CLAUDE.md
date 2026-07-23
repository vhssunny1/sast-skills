# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What This Project Is

An LLM-powered SAST pipeline for **polyglot repositories** (Java, Python, TypeScript/React, or any combination) implemented entirely as Claude Code slash commands (`.claude/commands/*.md`). There is no compiled code — the "implementation" is a set of prompt-driven skills that Claude executes in parallel groups where possible, sequentially where dependencies exist. SCA (dependency CVE scanning) is explicitly out of scope.

The pipeline auto-detects languages, routes to the right crawl/find-vulns skills, runs cross-language taint analysis for polyglot repos, and produces SARIF + Markdown reports with CVSS 3.1 scores per finding.

## Running a Scan

Full pipeline against any repo:
```
/sast-full-scan <repo-path>
/sast-full-scan <repo-path> --ground-truth <ground-truth.md>   # with precision/recall
/sast-full-scan <repo-path> --dast                              # also generate DAST test script
```

Individual skills can be invoked independently:
```
/detect-language <repo-path>
/crawl-python <repo-path>
/crawl-typescript <repo-path>
/config-audit <repo-path>
/find-vulns-python --crawl crawl-output.json
/find-vulns-typescript --crawl crawl-output.json
/find-vulns-java --crawl crawl-output.json
/cross-language-taint --findings findings.json --crawl crawl-output.json
/taint-trace --findings findings.json --crawl crawl-output.json
/validate-findings --findings findings.json
/scan-report --findings findings.json
/generate-fix FINDING-001
/scan-metrics --run-dir sast-runs/<timestamp>/
```

## Pipeline Architecture

`/sast-full-scan` runs a pre-step then three execution groups:

```
/detect-language    → language-manifest.json

/joern-parse        → cpg-output.json            (auto if Joern installed; graceful skip if not)
                      Exhaustive CPG: all graph-reachable taint paths, call graph, unreachable sinks.
                      find-vulns skills use this to prioritize files and pre-confirm chains.
                      Pass --skip-joern to bypass.

── GROUP 1 (concurrent) ──────────────────────────────────────────────
/crawl-python       → crawl-output-python.json   (Python repos)
/crawl-typescript   → crawl-output-typescript.json (TypeScript/React repos)
/config-audit       → findings.json (appended)   (reads .env, docker-compose, Dockerfiles, CI)
                    [merge crawl outputs → crawl-output.json]

── GROUP 2 (concurrent, after Group 1 merge) ─────────────────────────
/find-vulns-python  → findings-python.json        (loads cpg-output.json → CPG-guided + LLM discovery)
/find-vulns-typescript → findings-typescript.json (loads cpg-output.json → CPG-guided + LLM discovery)
/find-vulns-java    → findings-java.json          (loads cpg-output.json → CPG-guided + LLM discovery)
/codeql-scan        → codeql-output.json          (optional — pass --codeql; confirms/augments findings)
                    [merge all findings → findings.json]

── GROUP 3 (sequential) ──────────────────────────────────────────────
/cross-language-taint → findings.json (appended) (polyglot only — XL-* prefix findings)
/taint-trace        → findings.json (enriched; uses call_graph[] from cpg-output.json for caller lookup)
/validate-findings  → findings.json (enriched; codeql_confirmed findings get -0.25 fp_score reduction)
/scan-report        → scan-results.sarif + scan-summary.md (CVSS in both)
```

Supporting skills (run standalone or after full scan):
```
/scan-metrics       → sast-metrics.json (append-only; reads run-log.json for step_timings)
/generate-fix       → diff + explanation (standalone, reads findings.json)
/generate-dast-tests → dast-tests.py (optional — requires --dast flag)
```

`/sast-full-scan` writes intermediate snapshots to `sast-runs/<timestamp>/`, including a `run-log.json` with per-step timing, findings delta, and error capture.

## Key Files

| File | Purpose |
|---|---|
| `language-manifest.json` | Output of `/detect-language` — routes pipeline to correct skills |
| `cpg-output.json` | Joern CPG export — taint paths, call graph edges, unreachable sinks. Available when Joern is installed; stub with `available:false` otherwise. |
| `codeql-output.json` | CodeQL SARIF cross-reference — confirmed LLM findings + new CQL-* findings. Written only when `--codeql` passed. |
| `crawl-output.json` | Merged crawl output (polyglot: merged from `crawl-output-<lang>.json` after Group 1) |
| `findings.json` | Live findings file — progressively enriched by config-audit, find-vulns (CPG-guided + LLM), codeql-scan, cross-language-taint, taint-trace, validate-findings. Each finding includes `cvss_vector`, `cvss_score`, `cpg_guided`, and optionally `codeql_confirmed`. |
| `scan-results.sarif` | SARIF 2.1.0 output for IDE/GitHub Security tab — includes `cvss_vector`/`cvss_score` in `result.properties` |
| `scan-summary.md` | Human-readable Markdown report with fixes — includes CVSS per finding and score range in summary |
| `sast-metrics.json` | Append-only metrics history across scan runs — includes `step_timings[]` from `run-log.json` |
| `run-log.json` | Structured per-step audit log written by `/sast-full-scan` — timing, findings delta, errors per step |
| `sast-runs/<timestamp>/` | Immutable snapshot of every intermediate artifact per full-scan run |
| `dast-tests.py` | Generated DAST test script (only when `--dast` passed) |

## Skill Contracts

Each skill in `.claude/commands/` has a strict input/output contract. When modifying a skill:

- **`/detect-language`** — takes `<repo-path>`, writes `language-manifest.json`. Determines significant languages and routes to the correct crawl/find-vulns skills. Never reads source files — only counts extensions and reads package manifests.
- **`/joern-parse`** — takes `<repo-path>` + `language-manifest.json`, writes `cpg-output.json`. Runs Joern to build a CPG and exports taint paths, call graph, and unreachable sinks. Runs automatically if Joern is installed; skips gracefully with `available:false` stub otherwise. Never reads source files directly — Joern parses the repo.
- **`/crawl-python`** — takes `<repo-path>`, writes `crawl-output.json`. Classifies Python files by role (`entry_point`, `middleware`, `async_worker`, `dao`, `model`, `service`, `config`, `util`). Assigns `security_priority` scores.
- **`/crawl-typescript`** — takes `<repo-path>`, writes `crawl-output.json`. Classifies TypeScript/React files by role (`entry_point`, `middleware`, `service`, `dao`, `model`, `component`, `config`, `util`).
- **`/config-audit`** — takes `<repo-path>`, appends to `findings.json`. Reads `.env`, `docker-compose.yml`, `Dockerfile*`, CI files, `settings.py`, `constants.py`, `.cfg`/`.conf` files. Never reads application source code. Outputs `cvss_vector` and `cvss_score` on every finding. Runs in Group 1 concurrently with crawl skills.
- **`/find-vulns-python`** — takes `crawl-output.json` + optional `cpg-output.json`, writes `findings-python.json`. Loads CPG taint hints (Step 1.5) if available: boosts file priorities, pre-populates CPG candidates, uses call graph for caller resolution. Confirms CPG candidates via LLM file read. Still runs full LLM discovery for paths CPG may have missed. Hard constraint: findings come from reading the code.
- **`/find-vulns-typescript`** — same as find-vulns-python with TypeScript-specific sources/sinks. Writes `findings-typescript.json`.
- **`/find-vulns-java`** — same CPG integration as above with Java-specific patterns (Struts2/Spring). Writes `findings-java.json`.
- **`/codeql-scan`** — optional (`--codeql` flag). Takes `<repo-path>` + `language-manifest.json`. Runs CodeQL CLI in parallel with find-vulns (Group 2). Cross-references CodeQL SARIF against LLM findings: confirmed findings get `codeql_confirmed: true` + `-0.25 fp_score`. New CodeQL-only findings added as `CQL-*`. Skips gracefully if CodeQL CLI not installed.
- **`/cross-language-taint`** — takes `findings.json` + `crawl-output.json`, appends `XL-*` findings. Matches Python backend store points against TypeScript frontend render points. Also detects multi-hop prompt injection via RAG retrieval. Requires `language_boundary` on every XL finding.
- **`/taint-trace`** — enriches each finding with `taint_confirmed`, `confidence_after_trace`, `taint_path[]`, and `sanitization_gaps[]`. Uses `call_graph[]` from `cpg-output.json` to resolve callers without re-reading files. Does NOT add new findings.
- **`/validate-findings`** — adds `fp_score` and `validation_status` (`confirmed` / `likely_real` / `needs_review` / `likely_fp`). Applies `-0.25 fp_score` for `codeql_confirmed: true` findings. Sorts by severity → `cvss_score` DESC → `fp_score` ASC → `confidence_after_trace` DESC. Works only from `findings.json` — never reads source code. XL findings are never deduplicated against intra-language findings.
- **`/scan-report`** — produces SARIF 2.1.0 (`scan-results.sarif`) and Markdown summary (`scan-summary.md`). Includes `cvss_vector`/`cvss_score`/`cpg_guided`/`codeql_confirmed` in SARIF `result.properties`. Computes precision/recall when `--ground-truth` is provided.
- **`/generate-fix`** — takes a single `finding-id`, reads the vulnerable file, outputs a unified diff + explanation + test cases. One finding per invocation.
- **`/generate-dast-tests`** — takes `findings.json`, outputs `dast-tests.py` — a runnable behavioral test script for dynamic verification against a live app. Run only when `--dast` is passed to `/sast-full-scan`.
- **`/scan-metrics`** — reads run artifacts from `sast-runs/<timestamp>/` including `run-log.json`. Extracts `step_timings[]` (duration, findings delta, errors per step) and appends a full metrics record to `sast-metrics.json`.

## Finding ID Prefixes

| Prefix | Skill | Meaning |
|---|---|---|
| `CONFIG-*` | `/config-audit` | Configuration / deployment finding |
| `PY-*` | `/find-vulns-python` | Python source finding |
| `TS-*` | `/find-vulns-typescript` | TypeScript/React source finding |
| `JAVA-*` | `/find-vulns-java` | Java source finding |
| `XL-*` | `/cross-language-taint` | Cross-language taint path (requires `language_boundary`) |
| `CQL-*` | `/codeql-scan` | CodeQL-only finding (no LLM match found; LLM confirmation via taint-trace) |

## Important Constraints

- **Skills must be flat in `.claude/commands/`** — subdirectories are not recognized by Claude Code.
- **The repo needs `.git`** — Claude Code requires a git repository to discover project-level slash commands.
- **No pattern-matching against ground truth in `/find-vulns-*`** — findings must come from reading the code. Using a ground truth file as a lookup table is a correctness violation.
- **`/config-audit` never reads source code** — only configuration files. Speculation requiring source knowledge goes in `fix_hint`, not `description`.
- **XL findings require both sides** — `/cross-language-taint` must cite a `language_boundary` with backend file+line AND frontend file+line. Never create an XL finding with only one side confirmed.
- **CPG hints guide discovery, never replace it** — `cpg-output.json` boosts file priorities and pre-populates candidates, but `/find-vulns-*` skills must still read source files to confirm every candidate. A CPG path without LLM confirmation does NOT become a finding. This preserves the semantic accuracy of LLM analysis while gaining the graph's coverage completeness.
- **`/joern-parse` and `/codeql-scan` never read source files directly** — Joern and CodeQL parse the repo themselves. These skills only invoke the tools and process their output JSON/SARIF. The LLM-reads-code constraint applies only to find-vulns-* skills.
- **`CQL-*` findings bypass the find-vulns-from-code constraint** — CodeQL's dataflow engine read the code; the finding is legitimate. All CQL-* findings must still pass through `/taint-trace` for LLM semantic confirmation before being trusted.
- **Statelessness is intentional** — skills share no in-memory state. All cross-skill communication is through files (`crawl-output.json`, `cpg-output.json`, `codeql-output.json`, `findings.json`, `language-manifest.json`, `run-log.json`). This is a design choice, not a limitation — it enables parallel group execution without shared state.
- **Parallel groups require file-naming discipline** — when multiple crawl or find-vulns skills run in the same group, the orchestrator renames each skill's output to a language-specific file (`crawl-output-python.json`, `findings-typescript.json`) before the next skill runs, then merges after the group completes. Do not assume `crawl-output.json` or `findings.json` are the live outputs mid-group.
- **CVSS scores must be consistent with severity** — Critical findings must have `cvss_score` 9.0–10.0, High 7.0–8.9, Medium 4.0–6.9, Low 0.1–3.9. Mismatches between the label and the numeric score are a correctness violation.
- **Scan outputs are gitignored** — `findings.json`, `sast-runs/`, HTML reports, `crawl-output.json`, `scan-results.sarif`, and `dast-tests.py` are all excluded from version control. Only `.claude/commands/*.md`, `CLAUDE.md`, and `README.md` are committed.
- **`/find-vulns-*` coverage completeness is required** — every file with `security_priority` ≥ 2 in the crawl manifest must receive at least one full read/analysis pass. Silent truncation at tier boundaries is a correctness violation. Track `files_attempted` vs `files_in_manifest` in the findings output.
- **XL-PI-* findings do not require a frontend render sink** — standalone prompt injection findings fire when attacker-controlled content reaches LLM context without a trust boundary, even if there is no downstream `innerHTML`/XSS sink. `/cross-language-taint` is responsible for both XL (stored-XSS) and XL-PI (prompt injection) classes.
- **Explicitly out of scope — business logic bugs:** TOCTOU races, wrong exception-swallowing (broad `except` that silently drops a guard), incorrect migration ordering, wrong success-marking in state machines, and similar logic-correctness defects have no source→sink shape and are not modeled by any current skill. These are accepted gaps, not oversights. A future `logic-audit` skill could cover them if the team prioritizes it.
- **Explicitly out of scope — SCA/dependency CVE scanning:** Known CVEs in third-party packages are not reported. The pipeline focuses on first-party code vulnerabilities and configuration mistakes.
