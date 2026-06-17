Review findings.json from find-vulns and taint-trace. Score each finding for false positive likelihood. Remove duplicates. Produce a validated, ranked findings list ready for reporting.

This agent operates AFTER taint-trace. It does NOT look at source code — it reasons only about the evidence already captured in findings.json.

## Input

`$ARGUMENTS` format: `[--findings <path>]`

- `--findings <path>` — path to `findings.json` (default: `./findings.json`)

## Step 1 — Load findings

Read `findings.json`. If missing, print an error and stop.

Count findings by status:
- How many have `taint_confirmed: true`?
- How many have `taint_confirmed: false`?
- How many have `taint_confirmed: null` (untraced or partial)?

## Step 2 — Deduplicate

Two findings are duplicates if they share ALL of:
- Same `cwe`
- Same `file`
- Line numbers within ±5 of each other

When duplicates exist:
- Keep the one with higher `confidence_after_trace` (if set), else higher `confidence`
- Discard the rest
- Record discarded finding IDs in `validation_notes`

## Step 3 — Score each finding for false positive likelihood

For each finding, assign an `fp_score` from 0.0 (definitely real) to 1.0 (almost certainly false positive).

Use this scoring logic — add points for each condition that applies:

| Condition | FP score delta |
|---|---|
| `taint_confirmed: false` | +0.60 |
| `taint_confirmed: null` (untraced) | +0.20 |
| `confidence_after_trace` < 0.60 | +0.20 |
| `confidence` (original) < 0.65 | +0.15 |
| `taint_path` has 0 steps (no path recorded) | +0.15 |
| `taint_path` note mentions sanitization at any step | +0.30 |
| Sink is in a private method with no caller traced | +0.10 |
| Source description is vague ("unclear origin") | +0.10 |

Subtract points for conditions that increase confidence:

| Condition | FP score delta |
|---|---|
| `taint_confirmed: true` | -0.40 |
| `confidence_after_trace` ≥ 0.90 | -0.20 |
| `taint_path` has ≥ 2 steps (cross-file verified) | -0.10 |
| Severity is Critical and CWE maps to well-known injection class | -0.10 |

Cap `fp_score` at 0.0 minimum and 1.0 maximum.

## Step 4 — Assign validation status

Based on `fp_score`:

| fp_score | status | meaning |
|---|---|---|
| 0.00–0.25 | `confirmed` | High confidence real finding — include in report |
| 0.26–0.50 | `likely_real` | Probably real — include in report with a note |
| 0.51–0.74 | `needs_review` | Uncertain — include in report, flag for manual triage |
| 0.75–1.00 | `likely_fp` | Probably false positive — exclude from default report, keep in full output |

## Step 5 — Rank findings

Sort all findings with status `confirmed`, `likely_real`, or `needs_review` by:

1. Severity (critical → high → medium → low)
2. `fp_score` ascending (most confident first within same severity)
3. `confidence_after_trace` descending as tiebreaker

## Step 6 — Add precision estimate

After scoring, compute an estimated precision for this scan:

```
estimated_precision = confirmed_count / (confirmed_count + likely_fp_count)
```

This is not ground truth — it is an estimate based on taint confirmation and confidence scores.

## Step 7 — Write validated findings.json

Overwrite `findings.json` with the validated version. Add these fields to each finding:
- `fp_score` — the computed false positive score
- `validation_status` — one of: `confirmed`, `likely_real`, `needs_review`, `likely_fp`
- `validation_notes` — array of strings explaining the score (e.g. "taint_confirmed: false adds 0.60", "cross-file path verified subtracts 0.10")

Add a top-level `validation_summary`:

```json
{
  "validation_summary": {
    "total_before_dedup": 0,
    "duplicates_removed": 0,
    "total_after_dedup": 0,
    "confirmed": 0,
    "likely_real": 0,
    "needs_review": 0,
    "likely_fp": 0,
    "estimated_precision": 0.0
  }
}
```

## Output schema addition (per finding)

```json
{
  "fp_score": 0.05,
  "validation_status": "confirmed",
  "validation_notes": [
    "taint_confirmed: true → -0.40",
    "confidence_after_trace 0.97 ≥ 0.90 → -0.20",
    "cross-file taint path with 2 steps → -0.10",
    "severity Critical, CWE-78 (injection) → -0.10"
  ]
}
```

## Constraints

- Do NOT read any source code files — work only from findings.json
- Do NOT change `evidence`, `source`, `sink`, `taint_path`, or any field set by prior agents
- Do NOT remove findings — mark them `likely_fp` but keep them in the JSON
- `validation_notes` must explain every point added or subtracted, so a human can audit the scoring

## Downstream consumers

- `/scan-report` reads `validation_status` to decide what to include in the report
- `/scan-metrics` reads `validation_summary` for precision estimates
- `/generate-fix` should only be run on findings with status `confirmed` or `likely_real`

## Completion

```
validate-findings complete.
  Input findings   : <N>
  Duplicates removed: <N>
  Confirmed        : <N>
  Likely real      : <N>
  Needs review     : <N>
  Likely FP        : <N>
  Est. precision   : <N>%
  Output           : findings.json (validated in place)
```
