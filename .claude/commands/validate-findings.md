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
| `codeql_confirmed: true` (set by `/codeql-scan` when its independent dataflow engine hit the same sink) | -0.25 |
| `cpg_guided: true` and `cpg_source_confirmed: true` (Joern traced the full source→sink flow, not just a sink location) | -0.15 |
| `cpg_guided: true` and `cpg_source_confirmed: false` (Joern confirmed only the sink location — weaker signal, source still LLM-only) | -0.05 |

These three were documented in `CLAUDE.md`'s skill contracts as scoring inputs but were missing from this table (a real doc/implementation gap, not a design choice) — if you're adding a new upstream field that's meant to influence `fp_score`, add it here explicitly rather than assuming it's picked up automatically.

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

## Step 4b — Cross-service correlation

`config-audit` and `find-vulns-*` run as independent steps with no shared context — a config-only finding and a code-only finding can combine into something more severe than either alone, but nothing currently checks for that. This step works entirely from fields already present in `findings.json` (evidence, description, sink, cwe, file) — it does **not** re-read source code, consistent with this skill's existing constraint.

For every pair of findings in the current batch, check these specific correlations:

a. **OIDC/JWT replay:** one finding's `evidence`/`description` indicates a disabled OIDC nonce check or `JWT_ALGORITHM=none` (a `CONFIG-*` finding, typically CWE-287), and another finding's `sink`/`evidence` shows a `jwt.decode()`/`jwt.verify()` call with no nonce validation (from Q9's general JWT-validation-gaps check). Individually each is High; together they form a replay-attack chain — upgrade both to Critical and add a `correlated_with` field on each pointing at the other's `id`.

b. **CORS wildcard + credentialed requests:** one finding shows a CORS wildcard/reflected-origin misconfiguration (`CONFIG-*` CWE-942, or a TypeScript `Q10` finding), and another shows `credentials: 'include'` / `axios.defaults.withCredentials = true` / `XMLHttpRequest.withCredentials = true` reaching a cross-origin request. Together these mean authenticated responses are exfiltratable cross-origin, not just public data — upgrade to Critical if not already, and cross-reference via `correlated_with`.

c. **Exposed port without a corresponding auth layer:** a `config-audit` finding shows a non-standard port exposed in `docker-compose.yml` with no network isolation, and no `find-vulns-*` finding for that same service's routes shows an auth check present. This one is weaker evidence (absence of a finding is not proof of absence of auth) — only flag as a `needs_review`-tier note, do not auto-escalate severity from this correlation alone.

When a correlation is found, add `correlated_with: ["<other-finding-id>"]` and a `correlation_note` explaining the combined risk to both findings, and reflect any severity/CVSS change before Step 5's ranking runs. Most scans will have zero correlations — that's expected, not a sign this step did nothing.

## Step 5 — Rank findings

Sort all findings with status `confirmed`, `likely_real`, or `needs_review` by:

1. Severity (critical → high → medium → low)
2. `cvss_score` descending (highest numeric risk first within same severity band — this is the primary differentiator within a band, e.g. CVSS 9.8 before CVSS 9.1 both within Critical)
3. `fp_score` ascending (most confident first at equal CVSS score)
4. `confidence_after_trace` descending as tiebreaker

If `cvss_score` is absent (e.g. finding predates CVSS scoring), fall back to sort by `fp_score` ascending then `confidence_after_trace` descending.

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
- `correlated_with` and `correlation_note` — only present on findings Step 4b matched to another finding; absent otherwise

Preserve `cpg_guided`, `cpg_source_confirmed`, and `codeql_confirmed` on every finding that has them (set by `find-vulns-*`/`codeql-scan`) — `scan-report` reads these into SARIF `result.properties`. Do not drop them just because this step doesn't otherwise reference the finding's other fields.

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
    "severity Critical, CWE-798 → -0.10",
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
