Orchestrate a complete SAST pipeline run against any language repository. Detects the language first, then routes to language-specific crawl and find-vulns skills, then runs config-audit, optional cross-language taint merging, and the language-neutral taint-trace → validate-findings → scan-report pipeline.

Supports Java, Python, TypeScript/JavaScript, and polyglot repos.

---

## Why this order matters

```
DETECT-LANGUAGE  → "What language(s) is this repo? Which skills should run?"
                   Without this, crawl and find-vulns run with wrong assumptions.

╔══════════════════════════════════════════════════════════════╗
║  GROUP 1 — run all three concurrently                        ║
║                                                              ║
║  CRAWL-A        → "What files exist in language A?"          ║
║  CRAWL-B        → "What files exist in language B?"          ║
║  CONFIG-AUDIT   → "Any dangerous defaults or weak secrets?"  ║
║                                                              ║
║  crawl skills are independent of each other.                 ║
║  config-audit reads only config files — no crawl dependency. ║
╚══════════════════════════════════════════════════════════════╝
                   ↓ (merge crawl outputs when all done)

╔══════════════════════════════════════════════════════════════╗
║  GROUP 2 — run both concurrently, after Group 1 merges       ║
║                                                              ║
║  FIND-VULNS-A   → "Vulnerabilities in language A?"           ║
║  FIND-VULNS-B   → "Vulnerabilities in language B?"           ║
║                                                              ║
║  Both consume the merged crawl-output.json.                  ║
║  Neither depends on the other's output.                      ║
╚══════════════════════════════════════════════════════════════╝
                   ↓ (merge findings when all done)

GROUP 3 — sequential (each step depends on the previous):

CROSS-LANGUAGE-TAINT → "Does taint cross the Python→TypeScript boundary?" (polyglot only)
                   Matches Python stored-data sinks against TypeScript rendering sources.

TAINT-TRACE      → "Does attacker-controlled data actually flow to that sink?"
                   Cross-file verification. Converts guesses into confirmed paths.

VALIDATE         → "How confident are we in each finding? What is probably noise?"
                   Scores false-positive likelihood. Makes suppression auditable.

SCAN-REPORT      → "How do we communicate this to humans and tools?"
                   SARIF for tooling. Markdown for humans. Root-cause grouping.

GENERATE-DAST-TESTS (--dast only) → "How do I dynamically confirm these findings?"
                   Produces a runnable dast-tests.py. Off by default.
```

---

## Input

`$ARGUMENTS` format: `<repo-path> [--ground-truth <path>] [--out-dir <path>] [--skip-taint] [--skip-config-audit] [--dast] [--fresh] [--resume <run-id>]`

- `<repo-path>` — required. Path to the repository root (any language).
- `--ground-truth <path>` — optional. Path to ground truth file for precision/recall.
- `--out-dir <path>` — where to write all outputs (default: `./sast-runs/<timestamp>/`)
- `--skip-taint` — skip taint-trace (faster, higher FP rate)
- `--skip-config-audit` — skip config-audit step (use when no .env or docker-compose files present)
- `--dast` — optional. After scan-report, generate a DAST test script (`dast-tests.py`) from confirmed findings. Off by default.
- `--fresh` — force a new scan even if an incomplete prior run exists for this repo. Ignores auto-resume.
- `--resume <run-id>` — explicitly resume a specific prior run by ID (e.g. `--resume 20260722-103045`). Skips auto-detection.

If no repo path provided, print usage and stop.

---

## Step 0 — Auto-resume detection

**Run this before anything else, unless `--fresh` was passed.**

### Detection logic

1. Scan all `sast-runs/*/run-log.json` files in the current directory.
2. Filter to runs where `repo_path` matches the current `<repo-path>` argument (exact match).
3. From those, find runs where `status` is `"failed"` or `"in_progress"` (crashed mid-run).
4. If multiple exist, pick the most recent by `started_at`.
5. If `--resume <run-id>` was passed, use that run directly instead of auto-detecting.

### Outcomes

**No incomplete run found** (or `--fresh` passed):
→ Proceed to Step 1 as a fresh scan.

**Incomplete run found:**

Print:
```
Incomplete run detected: <run-id>  (failed at: <failed_at_step>)
Resuming from <failed_at_step> — skipping completed steps.
To start fresh instead: re-run with --fresh
To target a specific run: re-run with --resume <run-id>
```

Then:
1. Set `RESUMING = true`, `RESUME_RUN_DIR = sast-runs/<run-id>/`
2. Read the prior `run-log.json` — load `steps[]` to know which steps already have `status: "completed"`
3. Restore the **last good artifact** to the working directory using this table:

| `failed_at_step` | Artifact to restore | Restore as |
|---|---|---|
| `scan-report` | `<run-dir>/findings-validated.json` | `findings.json` |
| `generate-dast-tests` | `<run-dir>/findings-validated.json` | `findings.json` |
| `validate-findings` | `<run-dir>/findings-traced.json` | `findings.json` |
| `taint-trace` | `<run-dir>/findings-cross-lang.json` (if exists) or `findings-raw.json` | `findings.json` |
| `cross-language-taint` | `<run-dir>/findings-raw.json` | `findings.json` |
| `find-vulns` | `<run-dir>/findings-after-config-audit.json` (if exists) or nothing | `findings.json` |
| `config-audit` | — (no findings yet) | — |
| `crawl` or `detect-language` | — (start from that step, no artifact to restore) | — |

Also restore `crawl-output.json` from `<run-dir>/crawl-output.json` if the failed step is `find-vulns` or later.

4. Continue to Step 1 — but Step 1 will re-use the prior `run-manifest.json` and append to the prior `run-log.json` rather than creating new ones.

### Run-log behavior when resuming

When `RESUMING = true`:
- **Do not create a new `run-log.json`**. Load the prior one from `<run-dir>/run-log.json`.
- Update its top-level `status` back to `"in_progress"` and set `resumed_at: "<ISO 8601>"`.
- For each step that already has `status: "completed"` in the prior log — do NOT re-run it. Write a log entry:
  ```json
  { "step": "<name>", "status": "skipped", "skip_reason": "already completed in prior run" }
  ```
- Continue appending new step entries from the failed step onward.
- At finalization (Step 8), set `status: "success"` and `completed_at` as normal.

---

## Step 1 — Initialize run

**If `RESUMING = true`:** skip creating new files. Re-use `<RESUME_RUN_DIR>` as `<out-dir>`. Update `run-log.json` top-level: set `status: "in_progress"`, add `resumed_at: "<ISO 8601>"`. Print:
```
SAST full scan resuming.
  Repo    : <repo-path>
  Run dir : <out-dir>  (prior run)
```
Then skip to Step 2.

**If fresh scan:** Create output directory `./sast-runs/YYYYMMDD-HHMMSS/`

Write `run-manifest.json`:
```json
{
  "run_id": "YYYYMMDD-HHMMSS",
  "repo_path": "<absolute path>",
  "started_at": "<ISO 8601>",
  "ground_truth": "<path or null>",
  "skip_taint": false
}
```

Write `<out-dir>/run-log.json`:
```json
{
  "run_id": "YYYYMMDD-HHMMSS",
  "repo_path": "<absolute path>",
  "started_at": "<ISO 8601>",
  "status": "in_progress",
  "failed_at_step": null,
  "steps": []
}
```

### Resume skip rule (applies to every step below)

When `RESUMING = true`, before executing any step: check whether that step already has `status: "completed"` in the loaded prior `run-log.json`.

- **If already completed:** do not re-run the skill. Log `status: "skipped"`, `skip_reason: "already completed in prior run"`. Move to the next step.
- **If failed or missing:** this is the step to resume from — run it normally.

This check takes priority over all other skip conditions (e.g. `--skip-taint` is still honoured, but a step that already completed is never re-run regardless).

### Run-log protocol (apply at every step below)

Before executing each step, append to `steps[]` and rewrite `run-log.json`:
```json
{
  "step": "<skill-name>",
  "status": "started",
  "started_at": "<ISO 8601>",
  "findings_before": <integer count from findings.json, or null if not yet created>
}
```

When a step **completes**, update its entry (merge the following fields in):
```json
{
  "status": "completed",
  "completed_at": "<ISO 8601>",
  "duration_seconds": <elapsed seconds — estimate based on work volume if clock unavailable>,
  "findings_after": <integer count from findings.json, or null if step doesn't touch findings>,
  "output_artifacts": ["<filename-relative-to-out-dir>"],
  "error": null,
  "notes": { "<step-specific key/value pairs — see each step below>" }
}
```

**Parallel group entries:** For parallel groups, append all `"started"` entries to `run-log.json` together at the start of the group (before any skill runs), then update each entry to `"completed"` as each skill finishes. This ensures the log always shows what started, even if a later skill in the group fails.

When a step is **skipped**, append a complete entry (no "started" entry first):
```json
{
  "step": "<skill-name>",
  "status": "skipped",
  "skip_reason": "<human-readable reason>",
  "started_at": null,
  "completed_at": null,
  "duration_seconds": null,
  "findings_before": null,
  "findings_after": null,
  "output_artifacts": [],
  "error": null,
  "notes": {}
}
```

When a step **fails**, update its entry:
```json
{
  "status": "failed",
  "completed_at": "<ISO 8601>",
  "duration_seconds": <elapsed or null>,
  "error": "<error message or exception text>",
  "findings_after": null,
  "output_artifacts": []
}
```

Always rewrite `run-log.json` in full after every update so the file is always valid JSON and always reflects the current state.

Print:
```
SAST full scan starting.
  Repo    : <repo-path>
  Run dir : <out-dir>
```

---

## Step 2 — DETECT LANGUAGE

Run `/detect-language <repo-path>`.

Read `language-manifest.json`. Extract:
- `languages` — list of significant languages detected
- `primary_language` — the dominant one
- `polyglot` — true/false
- `frameworks` — map of language → framework
- `pipeline.crawl` — list of crawl skills to run (e.g. `["crawl-python", "crawl-typescript"]`)
- `pipeline.find_vulns` — list of find-vulns skills to run

Copy `language-manifest.json` to `<out-dir>/language-manifest.json`.

**Run-log:** Log step start before running. On completion log `"output_artifacts": ["language-manifest.json"]` and `"notes": {"languages": [...], "primary_language": "...", "polyglot": true|false, "frameworks": {...}, "crawl_skills": [...], "find_vulns_skills": [...]}`.

Print:
```
[0/4] detect-language complete — <languages> | primary: <primary_language> (<framework>) | polyglot: <yes/no>
      Pipeline: crawl: <crawl skills> | find-vulns: <find-vulns skills>
      Execution plan: Group 1 parallel: <crawl skills> + config-audit
                      Group 2 parallel: <find-vulns skills>
                      Group 3 sequential: cross-language-taint → taint-trace → validate → report
```

If `pipeline.crawl` is empty (unknown language), print a warning and stop.

---

## Step 3 — GROUP 1: CRAWL + CONFIG-AUDIT (parallel)

**Purpose:** Build the attack surface map and audit configuration files simultaneously. These three tasks have no dependencies on each other — crawl skills read source files, config-audit reads only config files.

**Run-log:** At the start of Group 1, append started entries for ALL Group 1 skills to `run-log.json` together, then execute them and update each to `completed` as it finishes.

### 3a — Crawl skills (run concurrently)

For each skill in `pipeline.crawl`, run it against `<repo-path>`:

**File naming for concurrent crawl:** Each crawl skill writes `crawl-output.json`. To prevent overwriting:
- After each crawl skill completes, immediately rename/copy its `crawl-output.json` to `crawl-output-<language>.json` (e.g. `crawl-output-python.json`, `crawl-output-typescript.json`) before the next crawl skill runs.
- Single-language repos skip this rename — use `crawl-output.json` directly.

**If only one crawl skill ran:** `crawl-output.json` is the final crawl output.

**If multiple crawl skills ran (polyglot):** after all crawl skills complete, merge:
1. Read each `crawl-output-<language>.json`
2. Combine `files[]` arrays (all files from all languages)
3. Combine `entry_points[]` arrays
4. Union `frameworks` (keep all)
5. Combine `dependencies[]` (deduplicate by name)
6. Set `language: "polyglot"` and `languages_detected: [...]`
7. Write the merged result to `crawl-output.json`

Copy final `crawl-output.json` to `<out-dir>/crawl-output.json`.

If crawl produces 0 files, print the error and stop.

**Run-log:** One entry per crawl skill. On completion log `"output_artifacts": ["crawl-output.json"]` and `"notes": {"skills_run": [...], "files_mapped": N, "entry_points": N, "frameworks": [...], "security_sensitive_deps": [...]}`.

### 3b — Config-audit (run concurrently with crawl)

**Purpose:** Find dangerous defaults, feature flags, and weak secrets in configuration files — without reading any source code. Runs in parallel with crawl because it has no dependency on crawl output.

If `--skip-config-audit` was passed:
**Run-log:** Log `status: "skipped"`, `skip_reason: "--skip-config-audit flag"`.

Otherwise: run `/config-audit <repo-path>` at the same time as the crawl skills.

Config-audit appends its findings to `findings.json` (or creates it). Copy updated file to `<out-dir>/findings-after-config-audit.json` once config-audit completes.

**Run-log:** On completion log `"output_artifacts": ["findings-after-config-audit.json"]` and `"notes": {"findings_added": N, "config_files_read": N, "dangerous_flags": [...], "weak_secrets_count": N, "supply_chain_issues": N}`.

### After Group 1 completes

Print:
```
[1/4] Group 1 complete (crawl + config-audit ran concurrently)
      crawl        → <N> files mapped (<languages>), <N> entry points | Framework(s): <list>
      config-audit → <N> configuration findings | Dangerous flags: <list>
```

---

## Step 4 — GROUP 2: FIND-VULNS (parallel)

**Purpose:** Identify candidate vulnerabilities by reading code and reasoning about data flow. All find-vulns skills for this repo can run at the same time — they read the same merged `crawl-output.json` and write to separate output files.

**Hard constraint:** find-vulns skills must derive findings from reading the code. They must never use the `--ground-truth` file or prior knowledge of the repo to generate findings.

**Run-log:** At the start of Group 2, append started entries for ALL find-vulns skills to `run-log.json` together.

**File naming for concurrent find-vulns:** Each find-vulns skill writes `findings.json`. To prevent overwriting:
- After each find-vulns skill completes, immediately rename/copy its `findings.json` to `findings-<language>.json` (e.g. `findings-python.json`, `findings-typescript.json`) before the next find-vulns skill runs.
- Single-language repos skip this rename — use `findings.json` directly.

Run all find-vulns skills against the merged `crawl-output.json`:
```
/find-vulns-<language> --crawl crawl-output.json
```

**If only one find-vulns skill ran:** `findings.json` is the final output (merge with config-audit findings if any).

**If multiple find-vulns skills ran (polyglot):** after all find-vulns skills complete, merge:
1. Read each `findings-<language>.json` and the config-audit findings already in `findings.json`
2. Renumber finding IDs to avoid collisions:
   - Java findings: `JAVA-001`, `JAVA-002`, ...
   - Python findings: `PY-001`, `PY-002`, ...
   - TypeScript findings: `TS-001`, `TS-002`, ...
   - Config findings: `CONFIG-001`, `CONFIG-002`, ... (retain from config-audit)
3. Combine all `findings[]` arrays into one
4. Recalculate `total_findings` and `findings_by_severity`
5. Write the merged result to `findings.json`

Copy `findings.json` to `<out-dir>/findings-raw.json`.

If 0 findings total (after merging all sources), note it but continue.

**Run-log:** One entry per find-vulns skill. On completion log `"output_artifacts": ["findings-raw.json"]` and `"notes": {"skills_run": [...], "files_scanned": N, "findings_added": N, "by_severity": {"critical": N, "high": N, "medium": N, "low": N}}`.

Print:
```
[2/4] Group 2 complete (find-vulns skills ran concurrently)
      <N> total candidate findings (<critical> critical / <high> high / <medium> medium / <low> low)
      find-vulns-python     → <N> findings
      find-vulns-typescript → <N> findings
      config-audit          → <N> findings (from Group 1)
```

---

## Step 4b — CROSS-LANGUAGE-TAINT (polyglot only)

**Purpose:** In polyglot repos (Python backend + TypeScript frontend), find stored-XSS paths where Python stores user-controlled data → TypeScript renders it without sanitization. Single-language scans miss these flows entirely. Also detects multi-hop prompt injection paths through RAG retrieval pipelines.

If `polyglot: false` in `language-manifest.json`, skip this step:
```
[2b] cross-language-taint skipped (single-language repo)
```
**Run-log:** Log `status: "skipped"`, `skip_reason: "single-language repo"`.

If polyglot: run `/cross-language-taint --findings findings.json --crawl crawl-output.json`

Cross-language-taint appends new cross-boundary findings to `findings.json`. Copy to `<out-dir>/findings-cross-lang.json`.

**Run-log:** Log step start. On completion log `"output_artifacts": ["findings-cross-lang.json"]` and `"notes": {"xl_findings_added": N, "language_boundaries_found": N}`.

Print:
```
[2b] cross-language-taint complete — <N> cross-boundary findings added
```

---

## Step 5 — TAINT-TRACE

**Purpose:** Verify cross-file taint paths hop by hop. A finding with a 1-file path is a guess; a finding with a verified 8-hop chain across 6 files is a confirmed vulnerability.

If `--skip-taint` was passed:
```
[3/4] taint-trace skipped (--skip-taint) — FP rate will be higher
```
**Run-log:** Log `status: "skipped"`, `skip_reason: "--skip-taint flag"`.

Otherwise: run `/taint-trace --findings findings.json --crawl crawl-output.json`

Enriches `findings.json` in place. Copy to `<out-dir>/findings-traced.json`.

**Run-log:** Log step start. On completion log `"output_artifacts": ["findings-traced.json"]` and `"notes": {"traced": N, "confirmed": N, "denied": N, "partial": N, "unreachable": N, "additional_files_read": N}`.

Print:
```
[3/4] taint-trace complete — <confirmed> confirmed / <denied> denied / <partial> partial
```

---

## Step 6 — VALIDATE-FINDINGS

**Purpose:** Score each finding for false-positive likelihood using an auditable rubric. Rank so developers see the most confident findings first.

Run `/validate-findings --findings findings.json`

Enriches `findings.json` in place. Copy to `<out-dir>/findings-validated.json`.

**Run-log:** Log step start. On completion log `"output_artifacts": ["findings-validated.json"]` and `"notes": {"confirmed": N, "likely_real": N, "needs_review": N, "likely_fp": N, "duplicates_removed": N, "estimated_precision": 0.0}`.

Print:
```
[4/4] validate-findings complete — <confirmed> confirmed / <likely_real> likely real / <needs_review> review / <likely_fp> suppressed
      Estimated precision: <N>%
```

---

## Step 7 — SCAN-REPORT

**Purpose:** Produce SARIF 2.1.0 for tooling and Markdown for humans. Group findings by root cause.

Run `/scan-report --findings findings.json --ground-truth <path if provided>`

Writes `scan-results.sarif` and `scan-summary.md`. Copy both to `<out-dir>`.

**Run-log:** Log step start. On completion log `"output_artifacts": ["scan-results.sarif", "scan-summary.md"]` and `"notes": {"sarif_results": N, "precision": <float or null>, "recall": <float or null>, "ground_truth_used": true|false}`.

Print:
```
scan-report complete — scan-results.sarif and scan-summary.md written
```

---

## Step 7b — GENERATE-DAST-TESTS (optional — only when --dast is passed)

**Purpose:** Turn confirmed findings into a runnable behavioral test script for dynamic verification against a live application.

If `--dast` was NOT passed:
**Run-log:** Log `status: "skipped"`, `skip_reason: "--dast not passed"`.

If `--dast` was passed: run `/generate-dast-tests --findings findings.json --base-url <base_url>`

Where `<base_url>` defaults to `http://localhost:8088` if not inferable from the repo (check docker-compose port mappings in the run's config-audit output).

Writes `dast-tests.py`. Copy to `<out-dir>/dast-tests.py`.

**Run-log:** Log step start. On completion log `"output_artifacts": ["dast-tests.py"]` and `"notes": {"tests_generated": N, "base_url": "<url>", "findings_covered": N}`.

Print:
```
generate-dast-tests complete — dast-tests.py written
     Run AFTER starting the application:
       docker compose up -d   (wait ~2 min)
       python dast-tests.py
```

---

## Step 8 — Finalize

Update `run-manifest.json`:
```json
{
  "completed_at": "<ISO 8601>",
  "status": "success",
  "language": "<primary language>",
  "polyglot": false,
  "frameworks": {},
  "total_findings": 0,
  "confirmed": 0,
  "likely_real": 0,
  "suppressed": 0,
  "precision_estimate": 0.0
}
```

Copy final `findings.json` to `<out-dir>/findings-final.json`.

Update `run-log.json`: set `"status": "success"` and `"completed_at": "<ISO 8601>"` at the top level. Rewrite the file.

Print final summary:
```
SAST full scan complete.
  Run dir   : <out-dir>
  Resumed   : yes (from <failed_at_step>)  ← only print this line when RESUMING = true
  Language  : <language(s)> (<framework(s)>)

  Execution groups:
    Group 1 (parallel) : crawl + config-audit  → <wall-clock savings vs sequential>
    Group 2 (parallel) : find-vulns skills     → <wall-clock savings vs sequential>
    Group 3 (sequential): cross-lang → taint-trace → validate → report

  Pipeline results:
    detect-language       → <languages> detected
    crawl                 → <N> files mapped, <N> entry points
    config-audit          → <N> configuration findings
    find-vulns            → <N> candidate findings
    cross-language-taint  → <N> cross-boundary findings (or "skipped")
    taint-trace           → <N> confirmed / <N> denied / <N> partial
    validate              → <N> confirmed / <N> likely_real / <N> suppressed
    precision est.        → <N>%

  Findings breakdown:
    <critical> critical
    <high> high
    <medium> medium
    <low> low
    <suppressed> suppressed (likely FP)

  Recall : <N>% vs ground truth  (or "not computed")

  Outputs written to <out-dir>/:
    language-manifest.json  — language and framework detection
    crawl-output.json       — file map + routes (merged for polyglot)
    findings-after-config-audit.json — config findings snapshot
    findings-raw.json       — candidates from find-vulns (merged)
    findings-traced.json    — after taint-trace
    findings-validated.json — after scoring + ranking
    findings-final.json     — final enriched findings
    scan-results.sarif      — SARIF 2.1.0 for IDE/GitHub
    scan-summary.md         — human-readable report with fixes
    run-manifest.json       — run metadata
    run-log.json            — structured per-step audit log (timing, findings delta, errors)
    dast-tests.py           — DAST confirmation script (only if --dast was passed)
```

---

## Error handling

If any step fails:
1. Print which step failed and the error
2. Save outputs produced so far to `<out-dir>`
3. Update `run-manifest.json` with `"status": "failed"` and `"failed_at_step": "<step>"`
4. Update the failing step's entry in `run-log.json` with `"status": "failed"`, `"error": "<message>"`, `"completed_at": "<ISO 8601>"`
5. Set top-level `run-log.json` fields `"status": "failed"` and `"failed_at_step": "<step>"`; rewrite the file
6. For parallel group failures: if one skill in a group fails, complete the other skills in the group before stopping — partial group output is better than none
7. Stop after the group completes — do not attempt subsequent groups with incomplete input

---

## Parallelism model

**Group 1 and Group 2 are concurrent execution groups.** Within each group, invoke all skills and proceed without waiting for each to finish before starting the next. The constraint is that all Group 1 skills must complete before Group 2 begins (because find-vulns needs the merged crawl output).

**File conflict handling:** Both crawl skills and both find-vulns skills write to the same default filename (`crawl-output.json`, `findings.json`). Resolve this by saving each skill's output to a language-specific file immediately after it completes, before the next skill runs:
- `crawl-output.json` → `crawl-output-python.json` (after crawl-python)
- `crawl-output.json` → `crawl-output-typescript.json` (after crawl-typescript)
- `findings.json` → `findings-python.json` (after find-vulns-python)
- `findings.json` → `findings-typescript.json` (after find-vulns-typescript)

Then merge to `crawl-output.json` / `findings.json` after the group completes.

**Single-language repos:** Groups 1 and 2 each have only one crawl/find-vulns skill. There is no concurrent execution within the group and no file renaming needed — the parallelism benefit comes only from config-audit running alongside the single crawl skill in Group 1.

---

## Constraints

- Always copy intermediate outputs to `<out-dir>` before the next group begins
- `/find-vulns-*` skills must never consult the `--ground-truth` file — that is only for `scan-report`'s precision/recall computation
- For polyglot repos: merge all crawl outputs into one `crawl-output.json` before starting any find-vulns skill
- Merge all find-vulns outputs (including config-audit findings) into one `findings.json` before starting cross-language-taint
- Group 3 is strictly sequential — each step depends on the previous step's enrichment of `findings.json`

---

## Invocation examples

```bash
# Normal run — auto-resumes if a prior incomplete run exists for this repo
/sast-full-scan my-repo

# Force fresh scan, ignore any incomplete prior run
/sast-full-scan my-repo --fresh

# Resume a specific prior run by ID (when multiple incomplete runs exist)
/sast-full-scan my-repo --resume 20260722-103045

# Java repo with precision/recall
/sast-full-scan dvja --ground-truth dvja-ground-truth.MD

# Python/FastAPI + React (polyglot) — auto-detected, Groups 1+2 run concurrently
/sast-full-scan genai-migration-assistant-dev

# Fast pass — skip taint trace
/sast-full-scan my-repo --skip-taint

# Custom output directory
/sast-full-scan my-repo --out-dir ./reports/sprint-42/

# Full pipeline + DAST script generation
/sast-full-scan my-repo --dast
```
