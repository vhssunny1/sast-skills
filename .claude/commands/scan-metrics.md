Compute and persist operational and quality metrics for a completed SAST scan run. Tracks token usage, timing, finding counts, precision/recall, and trends across runs.

## Input

`$ARGUMENTS` format: `[--run-dir <path>] [--metrics-db <path>]`

- `--run-dir <path>` — path to a completed sast-full-scan run directory (default: most recent `./sast-runs/*/`)
- `--metrics-db <path>` — path to the metrics history file (default: `./sast-metrics.json`)

## Step 1 — Load run artifacts

From `<run-dir>`, read:
- `run-manifest.json` — run ID, timestamps, repo path, step list
- `run-log.json` — structured per-step audit log (timing, findings delta, errors per step)
- `findings-raw.json` — finding count before validation (from find-vulns)
- `findings-validated.json` — finding count and validation breakdown (after validate-findings)
- `findings-final.json` — final enriched findings
- `scan-summary.md` — check if present (indicates scan-report ran)

If `run-manifest.json` is missing or status is not `success`, note the incomplete run but still compute whatever metrics are available. If `run-log.json` is missing (pre-dates this feature), set `step_timings: null` in the metrics record.

## Step 2 — Compute operational metrics

### Timing

From `run-manifest.json`:
```
total_duration_seconds = completed_at - started_at
```

### Per-step timing (from run-log.json)

If `run-log.json` is present, extract `step_timings` — one entry per step in `steps[]`:

```json
{
  "step": "<skill-name>",
  "status": "completed" | "skipped" | "failed",
  "duration_seconds": <integer or null>,
  "findings_before": <integer or null>,
  "findings_after": <integer or null>,
  "findings_delta": <findings_after - findings_before, or null>,
  "error": null | "<message>",
  "notes": { <forwarded verbatim from run-log step entry> },
  "usage": { <forwarded verbatim from run-log step entry, or null if absent> }
}
```

Compute `findings_delta = findings_after - findings_before` for each step where both are non-null. This shows which step introduced the most findings (find-vulns) and which reduced them (validate-findings suppressing FPs).

### Token usage & cost (from run-log.json)

If a step entry has a `usage` object (added by the harness CLI/API path — not present when a step ran through `/sast-full-scan` as a slash command, since that path has no access to the underlying CLI's JSON envelope), forward it verbatim per-step, and also sum a run-level total:

```
token_usage_totals = run-log.json's own top-level "token_usage_totals" field if present,
                     otherwise sum each step's usage.{input_tokens, output_tokens,
                     cache_creation_input_tokens, cache_read_input_tokens, cost_usd}
```

If no step in `run-log.json` has a `usage` field, set `token_usage_totals: null` in the metrics record rather than a zeroed object — null means "not tracked for this run," zero would wrongly imply a free run.

### Finding pipeline attrition

```
raw_findings        = total_findings in findings-raw.json
after_taint         = total_findings in findings-traced.json (if exists)
after_validation    = total_findings in findings-validated.json

attrition_rate = (raw_findings - confirmed_findings) / raw_findings
```

This shows how many candidate findings survived to the confirmed stage.

## Step 3 — Compute quality metrics

From `findings-final.json` `validation_summary`:

```
confirmed_count   = validation_summary.confirmed
likely_real_count = validation_summary.likely_real
needs_review_count = validation_summary.needs_review
likely_fp_count   = validation_summary.likely_fp

estimated_precision = validation_summary.estimated_precision
```

From `findings-final.json` `taint_summary` (if present):
```
taint_confirmation_rate = confirmed / traced
```

### Findings by severity

Count from `findings-final.json` where `validation_status` in (`confirmed`, `likely_real`):
```
critical_count = ...
high_count     = ...
medium_count   = ...
low_count      = ...
```

### Coverage

```
files_with_findings = count of unique `file` values in confirmed+likely_real findings
total_files_scanned = total_files from crawl-output.json
coverage_pct        = files_with_findings / total_files_scanned * 100
```

### Precision / Recall (if ground truth was used)

Extract from `scan-summary.md` or `run-manifest.json` if recorded:
```
true_positives  = ...
false_positives = ...
false_negatives = ...
precision       = TP / (TP + FP)
recall          = TP / (TP + FN)
f1              = 2 * P * R / (P + R)
```

If not available, record as null.

## Step 4 — Load metrics history

Read `sast-metrics.json` if it exists. This file is a list of run metric records.

If it does not exist, initialize it as an empty list `[]`.

## Step 5 — Detect trends

If there are 2 or more prior runs for the same `repo_path`:

Compare current run against the previous run for the same repo:
- `finding_delta` = current confirmed_count - previous confirmed_count (positive = more findings)
- `precision_delta` = current estimated_precision - previous estimated_precision
- `new_cwes` = CWE IDs in current run not seen in previous run
- `resolved_cwes` = CWE IDs in previous run not seen in current run

## Step 6 — Build metrics record

```json
{
  "run_id": "YYYYMMDD-HHMMSS",
  "repo_path": "<absolute path>",
  "scanned_at": "<ISO 8601>",
  "operational": {
    "total_duration_seconds": 0,
    "steps_completed": ["crawl", "find-vulns", "taint-trace", "validate-findings", "scan-report"],
    "files_scanned": {
      "java": 0,
      "jsp": 0,
      "xml": 0,
      "total": 0
    },
    "step_timings": [
      {
        "step": "detect-language",
        "status": "completed",
        "duration_seconds": 0,
        "findings_before": null,
        "findings_after": null,
        "findings_delta": null,
        "error": null,
        "notes": {},
        "usage": null
      }
    ],
    "token_usage_totals": null
  },
  "pipeline": {
    "raw_findings": 0,
    "after_taint_trace": 0,
    "after_validation": 0,
    "attrition_rate": 0.0,
    "taint_confirmation_rate": 0.0
  },
  "quality": {
    "confirmed": 0,
    "likely_real": 0,
    "needs_review": 0,
    "likely_fp": 0,
    "estimated_precision": 0.0,
    "recall": null,
    "f1": null,
    "true_positives": null,
    "false_positives": null,
    "false_negatives": null
  },
  "findings_by_severity": {
    "critical": 0,
    "high": 0,
    "medium": 0,
    "low": 0
  },
  "findings_by_cwe": {
    "CWE-89": 0
  },
  "coverage": {
    "files_with_findings": 0,
    "total_files": 0,
    "coverage_pct": 0.0
  },
  "trends": {
    "finding_delta": null,
    "precision_delta": null,
    "new_cwes": [],
    "resolved_cwes": []
  }
}
```

## Step 7 — Append and write

Append the new metrics record to the loaded history list. Write the updated list back to `sast-metrics.json`.

## Step 8 — Print metrics report

```
scan-metrics complete.
  Run       : <run_id>
  Repo      : <repo_path>
  Duration  : <Ns>

  Pipeline attrition:
    Raw findings       : <N>
    After taint-trace  : <N>
    After validation   : <N>
    Attrition rate     : <N>%

  Quality:
    Confirmed          : <N>
    Likely real        : <N>
    Needs review       : <N>
    Suppressed (FP)    : <N>
    Est. precision     : <N>%
    Recall             : <N>% (or "not computed")
    F1                 : <N>% (or "not computed")

  Severity breakdown:
    Critical : <N>
    High     : <N>
    Medium   : <N>
    Low      : <N>

  Coverage   : <N>/<total> files (<N>%)

  Per-step timings (from run-log.json):
    <step-name>  : <Ns> — <findings_delta> findings (<status>)
    ...
    (omit if run-log.json absent)

  Token usage & cost (from run-log.json, harness CLI/API runs only):
    Total cost      : $<N> (or "not tracked" if no step has a usage field)
    Input tokens    : <N> (incl. cache read/write)
    Output tokens   : <N>

  Trends vs previous run:
    Finding delta     : <+N/-N> (or "first run")
    Precision delta   : <+N/-N>%
    New CWEs          : <list or "none">
    Resolved CWEs     : <list or "none">

  Metrics saved to : sast-metrics.json
```

## Constraints

- Do NOT read any source code — work only from run artifacts and the metrics DB
- Append to `sast-metrics.json` — never overwrite the whole history
- If a field cannot be computed (step was skipped, file missing), record it as `null` — do not estimate
- Trends are only computed when there is at least one prior run for the same `repo_path`

## Downstream use

- `sast-metrics.json` can be parsed by dashboards, CI scripts, or future runs of this skill to track progress over time
- Feed into `/scan-report` as a trend summary if integrated
