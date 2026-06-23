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

**Exception — cross-language findings are never deduplicated against intra-language findings:** If one finding has a `language_boundary` field (set by `/cross-language-taint`, prefix `XL-`) and the other does not, they represent different attack vectors at the same code location and must both be kept regardless of line proximity. The XL finding captures the full cross-language path (e.g. repo submission → LLM generation → stored documentation → render); the intra-language finding captures a direct path (e.g. catch handler without HTML escaping). These are distinct exploits even when they point to adjacent lines in the same file.

When duplicates exist (after applying the exception above):
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

### Deployment context adjustment (config findings only)

For findings that carry a `deployment_context` field (set by `config-audit`), apply these additional adjustments **after** the standard scoring above:

| `deployment_context` | FP score delta | Rationale |
|---|---|---|
| `example_file` | +0.40 | Explicitly a sample — deployers know to replace values |
| `development_template` | +0.30 | Committed dev config with documented warnings — risk only if warnings ignored |
| `source_code_fallback` | -0.20 | Hardcoded in application logic — fires silently whether or not docs were read; override any template leniency |
| `production_config` | 0 | No template signals — treat at full severity |

**Important:** `source_code_fallback` always overrides other context signals. A value hardcoded in `constants.py` as a fallback is unconditional — even if the same value appears in a development template, the code path is separate and cannot be protected by deployment convention alone.

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

Config finding example with deployment context adjustment:

```json
{
  "fp_score": 0.30,
  "validation_status": "needs_review",
  "validation_notes": [
    "taint_confirmed: null (config finding, no taint trace) → +0.20",
    "confidence_after_trace not set → no adjustment",
    "deployment_context: development_template → +0.30",
    "adjacent warning comment: 'Make sure you set this to a unique secure random value on production'",
    "net fp_score: 0.50 → capped and rounded to 0.50 → needs_review"
  ]
}
```

Source code fallback example (hardcoded constant — deployment context does NOT reduce severity):

```json
{
  "fp_score": 0.00,
  "validation_status": "confirmed",
  "validation_notes": [
    "taint_confirmed: null (config finding) → +0.20",
    "deployment_context: source_code_fallback → -0.20 (overrides template leniency)",
    "severity Critical, CWE-521 → -0.10",
    "net fp_score: -0.10 → capped at 0.00 → confirmed"
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
