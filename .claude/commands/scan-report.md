Read validated findings.json and produce two outputs: a SARIF 2.1.0 file for tooling integration and a human-readable Markdown summary with precision/recall metrics.

## Input

`$ARGUMENTS` format: `[--findings <path>] [--ground-truth <path>] [--out-dir <path>]`

- `--findings <path>` — path to `findings.json` (default: `./findings.json`)
- `--ground-truth <path>` — optional path to ground truth file for precision/recall computation
- `--out-dir <path>` — directory to write outputs (default: current working directory)

## Step 1 — Load findings

Read `findings.json`. Extract:
- `repo_path`, `scanned_at`, `total_findings`
- `validation_summary` — overall stats
- `findings[]` — all findings, all statuses

Separate into two groups:
- **Report findings** — `validation_status` is `confirmed`, `likely_real`, or `needs_review`
- **Suppressed findings** — `validation_status` is `likely_fp`

## Step 2 — Compute metrics

### Precision / Recall (only if --ground-truth is provided)

Load the ground truth file. It must have entries with at least: `cwe`, `file` (basename is sufficient for matching), and optionally `line`.

For each report finding, check if it matches a ground truth entry:
- **True Positive (TP):** finding `cwe` matches a GT entry AND the `file` basename matches GT file
- **False Positive (FP):** finding has no matching GT entry
- **False Negative (FN):** GT entry has no matching finding

Compute:
```
Precision = TP / (TP + FP)
Recall    = TP / (TP + FN)
F1        = 2 * Precision * Recall / (Precision + Recall)
```

If no ground truth provided, note "precision/recall not computed — no ground truth provided."

### Coverage

```
Coverage = files_with_at_least_one_finding / total_files_scanned
```

## Step 3 — Write SARIF output

Write `scan-results.sarif` (JSON, SARIF 2.1.0 format).

```json
{
  "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
  "version": "2.1.0",
  "runs": [
    {
      "tool": {
        "driver": {
          "name": "SAST-Agent",
          "version": "1.0.0",
          "informationUri": "https://github.com/your-org/sast-agent",
          "rules": []
        }
      },
      "results": [],
      "artifacts": []
    }
  ]
}
```

**Populate `rules[]`** — one entry per unique CWE seen in report findings:
```json
{
  "id": "CWE-89",
  "name": "SQLInjection",
  "shortDescription": { "text": "SQL Injection" },
  "fullDescription": { "text": "User-controlled data reaches a SQL query without parameterization." },
  "helpUri": "https://cwe.mitre.org/data/definitions/89.html",
  "properties": { "tags": ["security", "correctness"] }
}
```

**Populate `results[]`** — one entry per report finding:
```json
{
  "ruleId": "CWE-89",
  "level": "error",
  "message": {
    "text": "<description field from finding>"
  },
  "locations": [
    {
      "physicalLocation": {
        "artifactLocation": {
          "uri": "<file path relative to repo root>",
          "uriBaseId": "%SRCROOT%"
        },
        "region": {
          "startLine": "<line number>",
          "snippet": { "text": "<evidence field>" }
        }
      },
      "logicalLocations": [
        {
          "name": "<method field>",
          "kind": "method"
        }
      ]
    }
  ],
  "properties": {
    "owasp": "<owasp field>",
    "severity": "<severity field>",
    "confidence": "<confidence_after_trace or confidence>",
    "validation_status": "<validation_status>",
    "source": "<source field>",
    "sink": "<sink field>",
    "fix_hint": "<fix_hint field>"
  }
}
```

SARIF level mapping:
- `critical` → `"error"`
- `high` → `"error"`
- `medium` → `"warning"`
- `low` → `"note"`

**Populate `artifacts[]`** — one entry per unique file referenced in results:
```json
{
  "location": { "uri": "<relative file path>", "uriBaseId": "%SRCROOT%" },
  "roles": ["analysisTarget"]
}
```

## Step 4 — Write Markdown summary

Write `scan-summary.md` with this structure:

---

```markdown
# SAST Scan Report

**Repo:** <repo_path>  
**Scanned:** <scanned_at>  
**Framework:** <framework from crawl>

---

## Summary

| Metric | Value |
|---|---|
| Total findings | N |
| Critical | N |
| High | N |
| Medium | N |
| Low | N |
| Suppressed (likely FP) | N |
| Estimated precision | N% |
| Recall (vs ground truth) | N% or "not computed" |
| Files with findings | N / total |

---

## Confirmed & Likely Real Findings

For each finding with status `confirmed` or `likely_real`, render:

### FINDING-001 — <severity uppercase> — <cwe> — <owasp>

| Field | Value |
|---|---|
| File | `<file>` line <line> |
| Method | `<method>` |
| Status | <validation_status> |
| Confidence | <confidence_after_trace or confidence> |

**What happens:**  
<description>

**Source:** <source>  
**Sink:** <sink>

**Evidence:**
\```java
<evidence>
\```

**Taint path:**  
<for each step in taint_path: "Step N — `file` → `method`: note">

**Fix:**  
<fix_hint>

---

## Needs Manual Review

List findings with `needs_review` status in a compact table:

| ID | CWE | File | Method | Confidence | Note |
|---|---|---|---|---|---|
| FINDING-003 | CWE-79 | UserAction.java | edit | 0.55 | Indirect taint path |

---

## Suppressed Findings (Likely False Positives)

List findings with `likely_fp` status in a compact table:

| ID | CWE | File | Reason suppressed |
|---|---|---|---|

---

## Precision / Recall

<If ground truth provided:>

| Metric | Value |
|---|---|
| True Positives | N |
| False Positives | N |
| False Negatives | N |
| Precision | N% |
| Recall | N% |
| F1 | N% |

**Missed findings (FN):**  
<List GT entries not matched by any finding>

**False positives (FP):**  
<List findings not matched by any GT entry>

<If no ground truth:>
Run with `--ground-truth dvja-ground-truth.MD` to compute precision and recall.

---

## Security Positive Signals

Scan `findings[]` for evidence that security controls ARE working. This section helps developers understand the security posture holistically — not just what's broken.

Extract:
1. **Verified sanitizers** — any finding where `taint_confirmed: false` and the taint_path note says "sanitization is effective", "taint chain BROKEN", or the method name contains `sanitize`, `clean`, `escape`, `encode`. Report the sanitizer name and what it protects against.
2. **Existing but uncalled guards** — from `sanitization_gaps[]` in any finding, extract instances of "Safety function `X` exists in `Y` but is not called here". The existence of these functions shows security awareness; the gap shows where to apply them.
3. **Framework-level protections** — look in `taint_path` notes for mentions of: CSRF protection enabled, `@protect()` or `@login_required` decorators, HTTPS-only cookies, rate limiting, allowlists in middleware.

Render as a compact table:

| Control | Where | Protects Against | Status |
|---|---|---|---|
| `nh3.clean()` | `superset/utils/core.py:554` | XSS via markdown content | Verified effective |
| `is_safe_host()` | `superset/utils/network.py` | SSRF | Exists but not called on test_connection path |
| CSRF protection | Flask-WTF default | CSRF | Enabled by default |

If no positive signals are found, omit this section rather than writing "none found."

---

## Recommendations

List the top 3 fix priorities based on severity + confirmation status.
```

---

## Step 5 — Write outputs

Write both files to `--out-dir` (default: current working directory):
- `scan-results.sarif`
- `scan-summary.md`

## Constraints

- Do NOT read any source code files — work only from findings.json
- SARIF must be valid JSON
- Every result in SARIF must have a valid `ruleId` that appears in the `rules[]` array
- Line numbers must be integers ≥ 1
- If a field is missing from a finding (e.g. `taint_path` not populated), omit it gracefully — do not error

## Downstream consumers

- `scan-results.sarif` → GitHub Security tab, VS Code SARIF viewer, IDE integrations
- `scan-summary.md` → PR comments, Slack, developer review
- `/scan-metrics` reads summary stats for trend tracking

## Completion

```
scan-report complete.
  Findings reported : <N> (<confirmed> confirmed / <likely_real> likely real / <needs_review> review)
  Suppressed        : <N> likely FP
  Precision         : <N>% (or "not computed")
  Recall            : <N>% (or "not computed")
  Outputs           : scan-results.sarif, scan-summary.md
```
