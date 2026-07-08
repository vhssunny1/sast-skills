# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What This Project Is

An LLM-powered SAST pipeline for **polyglot repositories** (Java, Python, TypeScript/React, or any combination) implemented entirely as Claude Code slash commands (`.claude/commands/*.md`). There is no compiled code — the "implementation" is a set of prompt-driven skills that Claude executes sequentially. SCA (dependency CVE scanning) is explicitly out of scope.

The pipeline auto-detects languages, routes to the right crawl/find-vulns skills, runs cross-language taint analysis for polyglot repos, and produces SARIF + Markdown + HTML reports.

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

Skills run sequentially; each writes a file consumed by the next:

```
/detect-language    → language-manifest.json
/crawl-python       → crawl-output.json          (Python repos)
/crawl-typescript   → crawl-output.json          (TypeScript/React repos)
/config-audit       → findings.json (appended)   (reads .env, docker-compose, Dockerfiles, CI)
/find-vulns-python  → findings.json
/find-vulns-typescript → findings.json (merged)
/find-vulns-java    → findings.json (merged)
/cross-language-taint → findings.json (appended) (polyglot only — XL-* prefix findings)
/taint-trace        → findings.json (enriched in place)
/validate-findings  → findings.json (enriched in place)
/scan-report        → scan-results.sarif + scan-summary.md
/scan-metrics       → sast-metrics.json (append-only history)
/generate-fix       → diff + explanation (standalone, reads findings.json)
/generate-dast-tests → dast-tests.py (optional — requires --dast flag)
```

`/sast-full-scan` is the orchestrator — it chains all of the above, writing intermediate snapshots to `sast-runs/<timestamp>/`.

## Key Files

| File | Purpose |
|---|---|
| `language-manifest.json` | Output of `/detect-language` — routes pipeline to correct skills |
| `crawl-output.json` | Output of last crawl run — merged for polyglot repos |
| `findings.json` | Live findings file — progressively enriched by config-audit, find-vulns, cross-language-taint, taint-trace, validate-findings |
| `scan-results.sarif` | SARIF 2.1.0 output for IDE/GitHub Security tab |
| `scan-summary.md` | Human-readable Markdown report with fixes |
| `sast-metrics.json` | Append-only metrics history across scan runs |
| `sast-runs/<timestamp>/` | Immutable snapshot of every intermediate artifact per full-scan run |
| `dast-tests.py` | Generated DAST test script (only when `--dast` passed) |

## Skill Contracts

Each skill in `.claude/commands/` has a strict input/output contract. When modifying a skill:

- **`/detect-language`** — takes `<repo-path>`, writes `language-manifest.json`. Determines significant languages and routes to the correct crawl/find-vulns skills. Never reads source files — only counts extensions and reads package manifests.
- **`/crawl-python`** — takes `<repo-path>`, writes `crawl-output.json`. Classifies Python files by role (`entry_point`, `middleware`, `async_worker`, `dao`, `model`, `service`, `config`, `util`). Assigns `security_priority` scores.
- **`/crawl-typescript`** — takes `<repo-path>`, writes `crawl-output.json`. Classifies TypeScript/React files by role (`entry_point`, `middleware`, `service`, `dao`, `model`, `component`, `config`, `util`).
- **`/config-audit`** — takes `<repo-path>`, appends to `findings.json`. Reads `.env`, `docker-compose.yml`, `Dockerfile*`, CI files, `settings.py`, `constants.py`, `.cfg`/`.conf` files. Never reads application source code.
- **`/find-vulns-python`** — takes `crawl-output.json`, writes `findings.json`. Must reason about data flow (source→sink). Hard constraint: findings come from reading the code, not from prior knowledge of the repo.
- **`/find-vulns-typescript`** — takes `crawl-output.json`, appends/merges to `findings.json`. Same hard constraint as find-vulns-python.
- **`/find-vulns-java`** — takes `crawl-output.json`, appends/merges to `findings.json`. Same hard constraint.
- **`/cross-language-taint`** — takes `findings.json` + `crawl-output.json`, appends `XL-*` findings. Matches Python backend store points against TypeScript frontend render points. Also detects multi-hop prompt injection via RAG retrieval. Requires `language_boundary` on every XL finding.
- **`/taint-trace`** — enriches each finding with `taint_confirmed`, `confidence_after_trace`, `taint_path[]`, and `sanitization_gaps[]`. Does NOT add new findings.
- **`/validate-findings`** — adds `fp_score` and `validation_status` (`confirmed` / `likely_real` / `needs_review` / `likely_fp`). Works only from `findings.json` — never reads source code. XL findings are never deduplicated against intra-language findings.
- **`/scan-report`** — produces SARIF 2.1.0 (`scan-results.sarif`) and Markdown summary (`scan-summary.md`). Computes precision/recall when `--ground-truth` is provided.
- **`/generate-fix`** — takes a single `finding-id`, reads the vulnerable file, outputs a unified diff + explanation + test cases. One finding per invocation.
- **`/generate-dast-tests`** — takes `findings.json`, outputs `dast-tests.py` — a runnable behavioral test script for dynamic verification against a live app. Run only when `--dast` is passed to `/sast-full-scan`.
- **`/scan-metrics`** — reads run artifacts from `sast-runs/<timestamp>/`, appends a metrics record to `sast-metrics.json`.

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
- **Statelessness is intentional** — skills share no in-memory state. All cross-skill communication is through files (`crawl-output.json`, `findings.json`, `language-manifest.json`). This is a design choice, not a limitation.
- **Scan outputs are gitignored** — `findings.json`, `sast-runs/`, HTML reports, `crawl-output.json`, `scan-results.sarif`, and `dast-tests.py` are all excluded from version control. Only `.claude/commands/*.md`, `CLAUDE.md`, and `README.md` are committed.
