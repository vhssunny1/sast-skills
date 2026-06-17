# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What This Project Is

An LLM-powered SAST pipeline for Java applications implemented entirely as Claude Code slash commands (`.claude/commands/*.md`). There is no compiled code — the "implementation" is a set of prompt-driven skills that Claude executes. The test target is DVJA (Damn Vulnerable Java Application), cloned to `dvja/`. SCA (dependency CVE scanning) is explicitly out of scope.

## Running a Scan

Full pipeline against DVJA with precision/recall measurement:
```
/sast-full-scan dvja --ground-truth dvja-ground-truth.MD
```

Individual skills can be invoked independently:
```
/crawl dvja
/find-vulns --crawl crawl-output.json
/taint-trace --findings findings.json --crawl crawl-output.json
/validate-findings --findings findings.json
/scan-report --findings findings.json --ground-truth dvja-ground-truth.MD
/generate-fix FINDING-001
/scan-metrics --run-dir sast-runs/<timestamp>/
```

## Pipeline Architecture

Skills run sequentially; each writes a file consumed by the next:

```
/crawl          → crawl-output.json
/find-vulns     → findings.json          (reads crawl-output.json)
/taint-trace    → findings.json (enriched in place)
/validate-findings → findings.json (enriched in place)
/scan-report    → scan-results.sarif + scan-summary.md
/scan-metrics   → sast-metrics.json (append-only history)
/generate-fix   → diff + explanation (standalone, reads findings.json)
```

`/sast-full-scan` is the orchestrator — it chains all of the above, writing intermediate snapshots to `sast-runs/<timestamp>/`.

## Key Files

| File | Purpose |
|---|---|
| `dvja-ground-truth.MD` | 12 known vulnerabilities in DVJA — the precision/recall baseline (GT-01 through GT-12) |
| `crawl-output.json` | Output of last `/crawl` run |
| `findings.json` | Live findings file — progressively enriched by taint-trace and validate-findings |
| `sast-metrics.json` | Append-only metrics history across scan runs |
| `sast-runs/<timestamp>/` | Immutable snapshot of every intermediate artifact per full-scan run |
| `Steps.MD` | Milestone plan (M1–M6) — current status and next steps |
| `Architecture-Comparison.MD` | Decision log for skills-based vs agent-based architecture |

## Skill Contracts

Each skill in `.claude/commands/` has a strict input/output contract. When modifying a skill:

- **`/crawl`** — takes `<repo-path>`, writes `crawl-output.json`. Classifies Java files by role (`entry_point`, `service`, `dao`, `model`, `filter_interceptor`, `config`, `util`).
- **`/find-vulns`** — takes `crawl-output.json`, writes `findings.json`. Must reason about data flow (source→sink), never pattern-match against a known-vulnerability checklist. This is a hard constraint: findings must be derived from reading the code, not from prior knowledge of DVJA.
- **`/taint-trace`** — enriches each finding with `taint_confirmed`, `confidence_after_trace`, `taint_path[]`, and `sanitization_gaps[]`. Does NOT add new findings.
- **`/validate-findings`** — adds `fp_score` and `validation_status` (`confirmed` / `likely_real` / `needs_review` / `likely_fp`). Works only from `findings.json` — never reads source code.
- **`/scan-report`** — produces SARIF 2.1.0 (`scan-results.sarif`) and Markdown summary (`scan-summary.md`). Computes precision/recall when `--ground-truth` is provided.
- **`/generate-fix`** — takes a single `finding-id`, reads the vulnerable file, outputs a unified diff + explanation + test cases. One finding per invocation.
- **`/scan-metrics`** — reads run artifacts from `sast-runs/<timestamp>/`, appends a metrics record to `sast-metrics.json`.

## Ground Truth Matching

When evaluating scan quality, a finding is a **True Positive** if its `cwe` and `file` basename both match a GT entry in `dvja-ground-truth.MD`. Recall target before Milestone 3 is ≥ 0.8 on the 10 statically-detectable GT findings (GT-11 is low-detectability, GT-07 is partial).

## Important Constraints

- **Skills must be flat in `.claude/commands/`** — subdirectories are not recognized by Claude Code.
- **The repo needs `.git`** — Claude Code requires a git repository to discover project-level slash commands. DVJA has its own `.git`; the outer SAST directory also has one.
- **No pattern-matching against ground truth in `/find-vulns`** — findings must come from reading the code. Using `dvja-ground-truth.MD` as a lookup table is a correctness violation that defeats the purpose of the SAST agent.
- **Statelessness is intentional** — skills share no in-memory state. All cross-skill communication is through files (`crawl-output.json`, `findings.json`). This is a design choice, not a limitation.
