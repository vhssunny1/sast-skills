Orchestrate a complete SAST pipeline run against any language repository. Detects the language first, then routes to language-specific crawl and find-vulns skills, then runs the language-neutral taint-trace → validate-findings → scan-report pipeline.

Supports Java, Python, TypeScript/JavaScript, and polyglot repos.

---

## Why this order matters

```
DETECT-LANGUAGE  → "What language(s) is this repo? Which skills should run?"
                   Without this, crawl and find-vulns run with wrong assumptions.

CRAWL            → "What is in this repo and what matters?"
                   Classifies files by role. Tells find-vulns which files receive
                   user input and which files touch dangerous sinks.

FIND-VULNS       → "What could be vulnerable — reading the code, not a checklist?"
                   Semantic source-to-sink reasoning. Broad by design.

TAINT-TRACE      → "Does attacker-controlled data actually flow to that sink?"
                   Cross-file verification. Converts guesses into confirmed paths.

VALIDATE         → "How confident are we in each finding? What is probably noise?"
                   Scores false-positive likelihood. Makes suppression auditable.

SCAN-REPORT      → "How do we communicate this to humans and tools?"
                   SARIF for tooling. Markdown for humans. Root-cause grouping.
```

---

## Input

`$ARGUMENTS` format: `<repo-path> [--ground-truth <path>] [--out-dir <path>] [--skip-taint]`

- `<repo-path>` — required. Path to the repository root (any language).
- `--ground-truth <path>` — optional. Path to ground truth file for precision/recall.
- `--out-dir <path>` — where to write all outputs (default: `./sast-runs/<timestamp>/`)
- `--skip-taint` — skip taint-trace (faster, higher FP rate)

If no repo path provided, print usage and stop.

---

## Step 1 — Initialize run

Create output directory: `./sast-runs/YYYYMMDD-HHMMSS/`

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

Print:
```
[0/5] detect-language complete — <languages> | primary: <primary_language> (<framework>) | polyglot: <yes/no>
      Pipeline: crawl: <crawl skills> | find-vulns: <find-vulns skills>
```

If `pipeline.crawl` is empty (unknown language), print a warning and stop.

---

## Step 3 — CRAWL

**Purpose:** Build the attack surface map. Role classification tells find-vulns which files receive user input and which touch dangerous sinks.

For each skill in `pipeline.crawl`:
- Run the skill against `<repo-path>`
- It writes `crawl-output.json` to the current directory

**If only one crawl skill ran:** use `crawl-output.json` directly.

**If multiple crawl skills ran (polyglot):** merge the outputs:
1. Read each `crawl-output.json` produced
2. Combine `files[]` arrays (all files from all languages)
3. Combine `entry_points[]` arrays
4. Union `frameworks` (keep all)
5. Combine `dependencies[]` (deduplicate by name)
6. Set `language: "polyglot"` and `languages_detected: [...]`
7. Write the merged result back to `crawl-output.json`

Copy `crawl-output.json` to `<out-dir>/crawl-output.json`.

If crawl produces 0 files, print the error and stop.

Print:
```
[1/5] crawl complete — <N> files mapped (<languages>), <N> entry points
      Framework(s): <list>
      Security-sensitive deps: <list>
```

---

## Step 4 — FIND-VULNS

**Purpose:** Identify candidate vulnerabilities by reading code and reasoning about data flow. Never pattern-match against a checklist.

**Hard constraint:** find-vulns skills must derive findings from reading the code. They must never use the `--ground-truth` file or prior knowledge of the repo to generate findings.

For each skill in `pipeline.find_vulns`:
- Run the skill: `/find-vulns-<language> --crawl crawl-output.json`
- It writes `findings.json`

**If only one find-vulns skill ran:** use `findings.json` directly.

**If multiple find-vulns skills ran (polyglot):** merge the findings:
1. Read each `findings.json` produced
2. Renumber finding IDs to avoid collisions:
   - Java findings: `JAVA-001`, `JAVA-002`, ...
   - Python findings: `PY-001`, `PY-002`, ...
   - TypeScript findings: `TS-001`, `TS-002`, ...
3. Combine all `findings[]` arrays into one
4. Recalculate `total_findings` and `findings_by_severity`
5. Write the merged result to `findings.json`

Copy `findings.json` to `<out-dir>/findings-raw.json`.

If 0 findings, note it but continue.

Print:
```
[2/5] find-vulns complete — <N> candidate findings (<critical> critical / <high> high / <medium> medium / <low> low)
```

---

## Step 5 — TAINT-TRACE

**Purpose:** Verify cross-file taint paths hop by hop. A finding with a 1-file path is a guess; a finding with a verified 8-hop chain across 6 files is a confirmed vulnerability.

If `--skip-taint` was passed:
```
[3/5] taint-trace skipped (--skip-taint) — FP rate will be higher
```

Otherwise: run `/taint-trace --findings findings.json --crawl crawl-output.json`

Enriches `findings.json` in place. Copy to `<out-dir>/findings-traced.json`.

Print:
```
[3/5] taint-trace complete — <confirmed> confirmed / <denied> denied / <partial> partial
```

---

## Step 6 — VALIDATE-FINDINGS

**Purpose:** Score each finding for false-positive likelihood using an auditable rubric. Rank so developers see the most confident findings first.

Run `/validate-findings --findings findings.json`

Enriches `findings.json` in place. Copy to `<out-dir>/findings-validated.json`.

Print:
```
[4/5] validate-findings complete — <confirmed> confirmed / <likely_real> likely real / <needs_review> review / <likely_fp> suppressed
      Estimated precision: <N>%
```

---

## Step 7 — SCAN-REPORT

**Purpose:** Produce SARIF 2.1.0 for tooling and Markdown for humans. Group findings by root cause.

Run `/scan-report --findings findings.json --ground-truth <path if provided>`

Writes `scan-results.sarif` and `scan-summary.md`. Copy both to `<out-dir>`.

Print:
```
[5/5] scan-report complete — scan-results.sarif and scan-summary.md written
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

Print final summary:
```
SAST full scan complete.
  Run dir   : <out-dir>
  Language  : <language(s)> (<framework(s)>)

  Pipeline results:
    detect-language  → <languages> detected
    crawl            → <N> files mapped, <N> entry points
    find-vulns       → <N> candidate findings
    taint-trace      → <N> confirmed / <N> denied / <N> partial
    validate         → <N> confirmed / <N> likely_real / <N> suppressed
    precision est.   → <N>%

  Findings breakdown:
    <critical> critical
    <high> high
    <medium> medium
    <low> low
    <suppressed> suppressed (likely FP)

  Recall : <N>% vs ground truth  (or "not computed")

  Outputs written to <out-dir>/:
    language-manifest.json  — language and framework detection
    crawl-output.json       — file map + routes
    findings-raw.json       — candidates from find-vulns
    findings-traced.json    — after taint-trace
    findings-validated.json — after scoring + ranking
    findings-final.json     — final enriched findings
    scan-results.sarif      — SARIF 2.1.0 for IDE/GitHub
    scan-summary.md         — human-readable report with fixes
    run-manifest.json       — run metadata
```

---

## Error handling

If any step fails:
1. Print which step failed and the error
2. Save outputs produced so far to `<out-dir>`
3. Update `run-manifest.json` with `"status": "failed"` and `"failed_at_step": "<step>"`
4. Stop — do not attempt subsequent steps with incomplete input

---

## Constraints

- Each skill runs **sequentially** — do not parallelize steps
- Always copy intermediate outputs to `<out-dir>` before the next step
- `/find-vulns-*` skills must never consult the `--ground-truth` file — that is only for `scan-report`'s precision/recall computation
- For polyglot repos: run all crawl skills first, merge, then run all find-vulns skills

---

## Invocation examples

```bash
# Java repo with precision/recall
/sast-full-scan dvja --ground-truth dvja-ground-truth.MD

# Python/FastAPI + React (polyglot) — auto-detected
/sast-full-scan genai-migration-assistant-dev

# Fast pass — skip taint trace
/sast-full-scan my-repo --skip-taint

# Custom output directory
/sast-full-scan my-repo --out-dir ./reports/sprint-42/
```
