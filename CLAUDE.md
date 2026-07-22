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

`/sast-full-scan` runs skills in three execution groups:

```
/detect-language    → language-manifest.json

── GROUP 1 (concurrent) ──────────────────────────────────────────────
/crawl-python       → crawl-output-python.json   (Python repos)
/crawl-typescript   → crawl-output-typescript.json (TypeScript/React repos)
/config-audit       → findings.json (appended)   (reads .env, docker-compose, Dockerfiles, CI)
                    [merge crawl outputs → crawl-output.json]

── GROUP 2 (concurrent, after Group 1 merge) ─────────────────────────
/find-vulns-python  → findings-python.json        (+ cvss_vector, cvss_score per finding)
/find-vulns-typescript → findings-typescript.json (+ cvss_vector, cvss_score per finding)
/find-vulns-java    → findings-java.json          (+ cvss_vector, cvss_score per finding)
                    [merge all findings → findings.json]

── GROUP 3 (sequential) ──────────────────────────────────────────────
/cross-language-taint → findings.json (appended) (polyglot only — XL-* prefix findings)
/taint-trace        → findings.json (enriched in place)
/validate-findings  → findings.json (enriched in place, sorted by cvss_score DESC within bands)
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
| `crawl-output.json` | Merged crawl output (polyglot: merged from `crawl-output-<lang>.json` after Group 1) |
| `findings.json` | Live findings file — progressively enriched by config-audit, find-vulns, cross-language-taint, taint-trace, validate-findings. Each finding includes `cvss_vector` and `cvss_score`. |
| `scan-results.sarif` | SARIF 2.1.0 output for IDE/GitHub Security tab — includes `cvss_vector`/`cvss_score` in `result.properties` |
| `scan-summary.md` | Human-readable Markdown report with fixes — includes CVSS per finding and score range in summary |
| `sast-metrics.json` | Append-only metrics history across scan runs — includes `step_timings[]` from `run-log.json` |
| `run-log.json` | Structured per-step audit log written by `/sast-full-scan` — timing, findings delta, errors per step |
| `sast-runs/<timestamp>/` | Immutable snapshot of every intermediate artifact per full-scan run |
| `dast-tests.py` | Generated DAST test script (only when `--dast` passed) |

## Skill Contracts

Each skill in `.claude/commands/` has a strict input/output contract. When modifying a skill:

- **`/detect-language`** — takes `<repo-path>`, writes `language-manifest.json`. Determines significant languages and routes to the correct crawl/find-vulns skills. Never reads source files — only counts extensions and reads package manifests.
- **`/crawl-python`** — takes `<repo-path>`, writes `crawl-output.json`. Classifies Python files by role (`entry_point`, `middleware`, `async_worker`, `dao`, `model`, `service`, `config`, `util`). Assigns `security_priority` scores.
- **`/crawl-typescript`** — takes `<repo-path>`, writes `crawl-output.json`. Classifies TypeScript/React files by role (`entry_point`, `middleware`, `service`, `dao`, `model`, `component`, `config`, `util`).
- **`/config-audit`** — takes `<repo-path>`, appends to `findings.json`. Reads `.env`, `docker-compose.yml`, `Dockerfile*`, CI files, `settings.py`, `constants.py`, `.cfg`/`.conf` files. Never reads application source code. Outputs `cvss_vector` and `cvss_score` on every finding. Runs in Group 1 concurrently with crawl skills.
- **`/find-vulns-python`** — takes `crawl-output.json`, writes `findings-python.json` (renamed by orchestrator). Must reason about data flow (source→sink). Outputs `cvss_vector` and `cvss_score` on every finding. Hard constraint: findings come from reading the code, not from prior knowledge of the repo.
- **`/find-vulns-typescript`** — takes `crawl-output.json`, writes `findings-typescript.json`. Same hard constraint and CVSS output as find-vulns-python.
- **`/find-vulns-java`** — takes `crawl-output.json`, writes `findings-java.json`. Same hard constraint and CVSS output.
- **`/cross-language-taint`** — takes `findings.json` + `crawl-output.json`, appends `XL-*` findings. Matches Python backend store points against TypeScript frontend render points. Also detects multi-hop prompt injection via RAG retrieval. Requires `language_boundary` on every XL finding.
- **`/taint-trace`** — enriches each finding with `taint_confirmed`, `confidence_after_trace`, `taint_path[]`, and `sanitization_gaps[]`. Does NOT add new findings.
- **`/validate-findings`** — adds `fp_score` and `validation_status` (`confirmed` / `likely_real` / `needs_review` / `likely_fp`). Sorts by severity → `cvss_score` DESC → `fp_score` ASC → `confidence_after_trace` DESC. Works only from `findings.json` — never reads source code. XL findings are never deduplicated against intra-language findings.
- **`/scan-report`** — produces SARIF 2.1.0 (`scan-results.sarif`) and Markdown summary (`scan-summary.md`). Includes `cvss_vector` and `cvss_score` in SARIF `result.properties` and in the Markdown per-finding table. Computes precision/recall when `--ground-truth` is provided.
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

## Important Constraints

- **Skills must be flat in `.claude/commands/`** — subdirectories are not recognized by Claude Code.
- **The repo needs `.git`** — Claude Code requires a git repository to discover project-level slash commands.
- **No pattern-matching against ground truth in `/find-vulns-*`** — findings must come from reading the code. Using a ground truth file as a lookup table is a correctness violation.
- **`/config-audit` never reads source code** — only configuration files. Speculation requiring source knowledge goes in `fix_hint`, not `description`.
- **XL findings require both sides** — `/cross-language-taint` must cite a `language_boundary` with backend file+line AND frontend file+line. Never create an XL finding with only one side confirmed.
- **Statelessness is intentional** — skills share no in-memory state. All cross-skill communication is through files (`crawl-output.json`, `findings.json`, `language-manifest.json`, `run-log.json`). This is a design choice, not a limitation — it enables parallel group execution without shared state.
- **Parallel groups require file-naming discipline** — when multiple crawl or find-vulns skills run in the same group, the orchestrator renames each skill's output to a language-specific file (`crawl-output-python.json`, `findings-typescript.json`) before the next skill runs, then merges after the group completes. Do not assume `crawl-output.json` or `findings.json` are the live outputs mid-group.
- **CVSS scores must be consistent with severity** — Critical findings must have `cvss_score` 9.0–10.0, High 7.0–8.9, Medium 4.0–6.9, Low 0.1–3.9. Mismatches between the label and the numeric score are a correctness violation.
- **Scan outputs are gitignored** — `findings.json`, `sast-runs/`, HTML reports, `crawl-output.json`, `scan-results.sarif`, and `dast-tests.py` are all excluded from version control. Only `.claude/commands/*.md`, `CLAUDE.md`, and `README.md` are committed.
