Orchestrate a complete SAST pipeline run against any language repository: crawl → find-vulns → taint-trace → validate-findings → scan-report. Write all intermediate and final outputs to a timestamped run directory.

This is the top-level orchestrator. It chains all skills in order, passing file outputs between them. Supports Java, Python, TypeScript/JavaScript, and polyglot repos.

---

## Why this order matters

Each stage answers a more precise question than the previous one and reduces noise for the next:

```
CRAWL          → "What is in this repo and what matters?"
                 Without this, find-vulns has no map of entry points vs utility files.

FIND-VULNS     → "What could be vulnerable — reading the code, not a checklist?"
                 Produces candidate findings from semantic source-to-sink reasoning.
                 Broad by design — some findings here will be false positives.

TAINT-TRACE    → "Does attacker-controlled data actually flow to that sink?"
                 Crosses file boundaries to confirm or deny each hop in the call chain.
                 Converts guesses into verified paths — or marks them likely FP.

VALIDATE       → "How confident are we in each finding, and what is probably noise?"
                 Scores false-positive likelihood; ranks findings; makes the cut explicit.
                 Developers only see what passed the bar — not every raw candidate.

SCAN-REPORT    → "How do we communicate this to humans and tools?"
                 SARIF for IDE/GitHub integration. Markdown for developer review.
                 Groups findings by root cause, not just by file.
```

The pipeline is **stateless between steps** — every skill reads files, writes files, and has no memory of prior steps. This means any step can be re-run independently, and any intermediate artifact can be inspected directly.

---

## Input

`$ARGUMENTS` format: `<repo-path> [--ground-truth <path>] [--out-dir <path>] [--skip-taint]`

- `<repo-path>` — required. Absolute or relative path to the repository root (any language)
- `--ground-truth <path>` — optional path to ground truth file for precision/recall in the report
- `--out-dir <path>` — where to write all outputs (default: `./sast-runs/<timestamp>/`)
- `--skip-taint` — skip the taint-trace step (faster but less accurate; increases FP rate)

If no repo path provided, print usage and stop.

---

## Step 1 — Initialize run

Create the output directory: `./sast-runs/YYYYMMDD-HHMMSS/` (use current timestamp).

Write `run-manifest.json` to the output directory:
```json
{
  "run_id": "YYYYMMDD-HHMMSS",
  "repo_path": "<absolute path>",
  "started_at": "<ISO 8601>",
  "steps": ["crawl", "find-vulns", "taint-trace", "validate-findings", "scan-report"],
  "skip_taint": false,
  "ground_truth": "<path or null>"
}
```

Print:
```
SAST full scan starting.
  Repo     : <repo-path>
  Run dir  : <out-dir>
  Pipeline : crawl → find-vulns → taint-trace → validate-findings → scan-report
```

---

## Step 2 — CRAWL

**Purpose:** Build the attack surface map. Without it, find-vulns has no way to distinguish entry points (where user data enters) from model files (where it doesn't). Role classification is what makes the next step efficient.

Run the `/crawl` skill against `<repo-path>`.

What crawl does:
1. Detects primary language(s) by file count — supports Java, Python, TypeScript, polyglot
2. Classifies every file into a role: `entry_point`, `service`, `dao`, `model`, `filter_interceptor`, `config`, `celery_task`, `util`
3. Extracts all HTTP routes from entry point files
4. Flags security-sensitive dependencies (PyJWT, GitPython, cryptography, etc.)

Produces `crawl-output.json`. Copy to `<out-dir>/crawl-output.json`.

If crawl fails or produces no files, print the error and stop — do not proceed.

Print status:
```
[1/5] crawl complete — <N> files (<language>), <N> entry points, framework: <framework>
      Languages: <detected languages>
      Security-sensitive deps: <list>
```

---

## Step 3 — FIND-VULNS

**Purpose:** Identify candidate vulnerabilities by reading the code and reasoning about data flow — not by pattern-matching against a checklist. This is the core of the SAST agent.

Run the `/find-vulns` skill using:
- `--crawl <out-dir>/crawl-output.json`

What find-vulns does:
1. Reads files in priority order: entry_points → daos → services → middleware → config
2. For each method, asks: what enters here? Where does it go? Is there a dangerous sink? Is there sanitization between source and sink?
3. Reports findings only when it can identify a specific source, a specific sink, and the absence of effective sanitization — grounded in the actual code read

**Hard constraint:** find-vulns must derive findings from reading the code. It must never use prior knowledge of the repo, known CVE lists, or ground truth files as a lookup table. Findings must come from the code, not from memory.

Produces `findings.json`. Copy to `<out-dir>/findings-raw.json`.

If find-vulns produces 0 findings, note it but continue — the report will say zero findings.

Print status:
```
[2/5] find-vulns complete — <N> candidate findings (<critical> critical / <high> high / <medium> medium / <low> low)
```

---

## Step 4 — TAINT-TRACE

**Purpose:** Verify that attacker-controlled data actually flows from source to sink across file boundaries. A finding with a 1-file path is a guess. A finding with a verified 8-hop path across 6 files is a confirmed vulnerability. This step is what separates SAST from grep.

Run the `/taint-trace` skill using:
- `--findings findings.json`
- `--crawl <out-dir>/crawl-output.json`

What taint-trace does:
1. For each candidate finding, reads only the files involved in that finding's call chain (not the whole codebase)
2. Traces: entry_point → service → DAO → sink, following how the tainted value propagates through method arguments, return values, field assignments, and string concatenation
3. Marks each finding: `taint_confirmed: true` (path verified), `false` (sanitization found — likely FP), or `null` (partial — could not verify one hop)
4. Adds `taint_path[]` (step-by-step chain with evidence at each hop) and `sanitization_gaps[]` (what protection is absent)

Enriches `findings.json` in place. Copy to `<out-dir>/findings-traced.json`.

If `--skip-taint` was passed, skip this step and print:
```
[3/5] taint-trace skipped (--skip-taint) — FP rate will be higher
```

Otherwise print:
```
[3/5] taint-trace complete — <confirmed> confirmed / <denied> denied / <partial> partial
      Additional files read: <N>
```

---

## Step 5 — VALIDATE-FINDINGS

**Purpose:** Score each finding for false-positive likelihood using a systematic, auditable rubric. Rank findings so developers see the most confident ones first. Make the suppression decision explicit and reversible.

Run the `/validate-findings` skill using:
- `--findings findings.json`

What validate-findings does:
1. Deduplicates findings with same CWE + file + line (±5)
2. Scores each finding on `fp_score` (0.0 = definitely real → 1.0 = definitely FP) using:
   - `taint_confirmed: true` → −0.40 (strong evidence)
   - `confidence_after_trace ≥ 0.90` → −0.20
   - Cross-file path with ≥ 2 steps → −0.10
   - `taint_confirmed: null` → +0.20
   - Low confidence scores → +0.15 to +0.20
3. Assigns `validation_status`: `confirmed` (fp ≤ 0.25), `likely_real` (≤ 0.50), `needs_review` (≤ 0.74), `likely_fp` (> 0.74)
4. Ranks by severity → fp_score → confidence

Enriches `findings.json` in place. Copy to `<out-dir>/findings-validated.json`.

Print status:
```
[4/5] validate-findings complete — <confirmed> confirmed / <likely_real> likely real / <needs_review> review / <likely_fp> suppressed
      Estimated precision: <N>%
```

---

## Step 6 — SCAN-REPORT

**Purpose:** Translate findings into formats developers and tools can act on. SARIF for machine consumption (GitHub Security, IDE plugins). Markdown for human review (PR comments, security Slack, developer reading).

Run the `/scan-report` skill using:
- `--findings findings.json`
- `--ground-truth <path>` (if provided)
- `--out-dir <out-dir>`

What scan-report does:
1. Produces `scan-results.sarif` (SARIF 2.1.0) — one rule per unique CWE, one result per finding, severity mapped to SARIF levels (`error`/`warning`/`note`)
2. Produces `scan-summary.md` — full human-readable report with: per-finding evidence + taint path + fix code, grouped recommendations by root cause, precision/recall table if ground truth provided
3. Groups related findings by root cause in recommendations (e.g. "these 4 findings all stem from the same header-trust design gap — fix one place, eliminate four findings")

Writes `scan-results.sarif` and `scan-summary.md` to `<out-dir>`.

Print status:
```
[5/5] scan-report complete — scan-results.sarif and scan-summary.md written
```

---

## Step 7 — Finalize

Record completion in `run-manifest.json`:
```json
{
  "completed_at": "<ISO 8601>",
  "status": "success",
  "summary": {
    "language": "<primary language>",
    "framework": "<framework>",
    "total_files_scanned": N,
    "total_findings": N,
    "confirmed": N,
    "likely_real": N,
    "needs_review": N,
    "suppressed": N,
    "precision_estimate": 0.0,
    "recall": 0.0
  }
}
```

Copy final `findings.json` to `<out-dir>/findings-final.json`.

Print final summary:
```
SAST full scan complete.
  Run dir   : <out-dir>
  Language  : <language> (<framework>)
  Duration  : <elapsed time>

  Pipeline results:
    crawl          → <N> files mapped, <N> entry points
    find-vulns     → <N> candidate findings
    taint-trace    → <N> confirmed / <N> denied / <N> partial
    validate       → <N> confirmed / <N> likely_real / <N> suppressed
    precision est. → <N>%

  Findings breakdown:
    <critical> critical
    <high> high
    <medium> medium
    <low> low
    <suppressed> suppressed (likely FP)

  Recall    : <N>% (vs ground truth) or "not computed"

  Outputs:
    crawl-output.json       — repo file map + routes
    findings-raw.json       — raw candidates from find-vulns
    findings-traced.json    — after taint-trace (paths verified)
    findings-validated.json — after scoring + ranking
    findings-final.json     — final enriched findings
    scan-results.sarif      — SARIF 2.1.0 for IDE/GitHub
    scan-summary.md         — human-readable report with fixes
    run-manifest.json       — run metadata + summary stats
```

---

## Error handling

If any step fails:
1. Print which step failed and the error
2. Save whatever outputs were produced so far to `<out-dir>`
3. Update `run-manifest.json` with `"status": "failed"` and `"failed_at_step": "<step>"`
4. Stop — do not attempt subsequent steps with incomplete input

---

## Constraints

- Each skill runs **sequentially** — do not run steps in parallel
- Always copy intermediate outputs to `<out-dir>` before the next step
- If `<out-dir>` already exists (re-run), do not delete it — overwrite individual files
- The `findings.json` in the working directory is the live, progressively-enriched file; snapshots in `<out-dir>` preserve each stage
- `/find-vulns` must never consult the `--ground-truth` file — that file is only for the report stage's precision/recall computation

---

## Invocation examples

```bash
# Full scan — any language
/sast-full-scan genai-migration-assistant-dev

# With ground truth for precision/recall
/sast-full-scan dvja --ground-truth dvja-ground-truth.MD

# Fast mode — skip taint trace
/sast-full-scan my-repo --skip-taint

# Custom output directory
/sast-full-scan my-repo --out-dir ./reports/sprint-42/
```

Expected output directory after run:
```
sast-runs/20260617-120000/
  run-manifest.json         ← run metadata + final summary
  crawl-output.json         ← repo file map (roles, routes, deps)
  findings-raw.json         ← find-vulns output (candidates only)
  findings-traced.json      ← after taint-trace (paths verified)
  findings-validated.json   ← after scoring + ranking
  findings-final.json       ← fully enriched, final state
  scan-results.sarif        ← SARIF 2.1.0 for tooling
  scan-summary.md           ← human report with evidence + fixes
```
