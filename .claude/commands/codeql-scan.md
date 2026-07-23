Run CodeQL security analysis against the repository and merge its findings into findings.json as a second-signal layer for validate-findings. Optional — only runs when `--codeql` is passed to sast-full-scan.

CodeQL provides exhaustive inter-procedural dataflow analysis using a compiled query database. It finds paths that the LLM may miss due to deep call chains or dynamic dispatch. The LLM has already found findings by this point; CodeQL's role is:
1. **Confirm** LLM findings that it also finds → reduce `fp_score`
2. **Surface** paths the LLM missed → add new findings with `source: "codeql"`
3. **Flag dead-code sinks** the LLM analyzed unnecessarily → inform future runs

This skill runs in parallel with find-vulns (Group 2) so it does not add wall time on the critical path.

---

## Input

`$ARGUMENTS` format: `<repo-path> --manifest language-manifest.json [--codeql-bin <path>] [--db-dir <path>] [--out-sarif <path>]`

- `<repo-path>` — required. Absolute path to the repository.
- `--manifest <path>` — path to `language-manifest.json` (default: `./language-manifest.json`)
- `--codeql-bin <path>` — path to `codeql` executable (default: auto-detect)
- `--db-dir <path>` — where to build the CodeQL database (default: `./codeql-db/`)
- `--out-sarif <path>` — where to write CodeQL's raw SARIF (default: `./codeql-results.sarif`)

---

## Step 1 — Detect CodeQL installation

Check for CodeQL CLI in this order:
1. `$CODEQL_HOME/codeql` if `$CODEQL_HOME` is set
2. `codeql` on `$PATH` (run `codeql version`)
3. `~/codeql/codeql`
4. Value of `--codeql-bin` flag

If not found:
```
codeql-scan: CodeQL CLI not found — skipping.
  Install : https://github.com/github/codeql-cli-binaries/releases
  Query packs: gh extensions install github/gh-codeql
  Effect  : codeql confirmation layer unavailable.
```
Write `codeql-output.json` with `"available": false` and stop. Pipeline continues normally.

---

## Step 2 — Determine language and query suite

Read `language-manifest.json`. Map languages to CodeQL language IDs and query suites:

| Language | CodeQL lang | Query suite |
|---|---|---|
| `typescript` / `javascript` | `javascript` | `javascript-security-extended.qls` |
| `python` | `python` | `python-security-extended.qls` |
| `java` / `kotlin` | `java` | `java-security-extended.qls` |

For polyglot repos, run one CodeQL database per language and merge outputs.

If the language is not supported by CodeQL, write stub and stop.

---

## Step 3 — Create CodeQL database

For each language:

```bash
codeql database create <db-dir>/<language>/ \
  --language=<codeql-lang> \
  --source-root=<repo-path> \
  --overwrite \
  --no-run-unnecessary-builds
```

For compiled languages (Java), CodeQL needs to intercept the build. If no build system is detected (no `pom.xml`, `build.gradle`, `Makefile`), pass `--build-mode=none` (CodeQL 2.15+):
```bash
codeql database create ... --build-mode=none
```

If database creation fails:
- Log the error
- Write `codeql-output.json` with `"available": false, "reason": "db_creation_failed"`
- Stop. Pipeline continues.

---

## Step 4 — Run security queries

For each database:
```bash
codeql database analyze <db-dir>/<language>/ \
  <query-suite> \
  --format=sarif-latest \
  --output=<out-sarif> \
  --threads=4 \
  --no-download
```

If `--no-download` fails (query packs not installed locally):
```bash
codeql database analyze <db-dir>/<language>/ \
  <query-suite> \
  --format=sarif-latest \
  --output=<out-sarif> \
  --threads=4
```
(Let CodeQL download from the registry if needed.)

Expected runtime: 2–15 minutes depending on repo size. This runs in parallel with find-vulns so it does not block the critical path.

---

## Step 5 — Parse CodeQL SARIF output

Read `<out-sarif>`. For each `result` in `runs[0].results[]`:

Extract:
- `ruleId` — CodeQL rule ID (e.g. `js/sql-injection`)
- `message.text` — description
- `locations[0].physicalLocation.artifactLocation.uri` — file path
- `locations[0].physicalLocation.region.startLine` — line number
- `level` — `"error"` / `"warning"` / `"note"`
- `codeFlows[0].threadFlows[0].locations[]` — taint path steps (if present)

Map CodeQL rule IDs to CWEs and OWASP:

| CodeQL rule prefix | CWE | OWASP |
|---|---|---|
| `*/sql-injection` | CWE-89 | A03:2021 |
| `*/xss` | CWE-79 | A03:2021 |
| `*/code-injection` | CWE-94 | A03:2021 |
| `*/command-injection` | CWE-78 | A03:2021 |
| `*/path-injection` | CWE-22 | A01:2021 |
| `*/ssrf` | CWE-918 | A10:2021 |
| `*/open-redirect` | CWE-601 | A01:2021 |
| `*/hardcoded-credentials` | CWE-798 | A02:2021 |
| `*/prototype-pollution` | CWE-1321 | A03:2021 |
| `*/unsafe-deserialization` | CWE-502 | A08:2021 |
| `*/regex-injection` | CWE-1333 | A03:2021 |
| `*/clear-text-logging` | CWE-312 | A02:2021 |
| `*/missing-origin-check` | CWE-942 | A05:2021 |

Map CodeQL level to severity:
- `"error"` → `"high"` (minimum; upgrade to `"critical"` for SQL/command injection)
- `"warning"` → `"medium"`
- `"note"` → `"low"`

---

## Step 6 — Cross-reference with LLM findings

Load `findings.json` (the current findings from find-vulns + config-audit).

For each CodeQL result, check if an existing LLM finding matches:

**Match criteria** (any two must be true):
- Same `cwe` (or CWE mapped from CodeQL rule ID)
- Same file (`uri` basename matches `finding.file` basename)
- Line within ±10 of each other

**If match found:**
- Add `"codeql_confirmed": true` to the existing LLM finding
- Add `"codeql_rule": "<ruleId>"` to the existing finding
- Reduce `fp_score` by 0.25 in validate-findings (pre-annotate with `"codeql_signal": "confirmed"`)
- Do NOT create a duplicate finding

**If NO match found (CodeQL found something LLM missed):**
- Create a new finding with `source: "codeql"` prefix on the ID: `CQL-001`, `CQL-002`, ...
- Populate from CodeQL SARIF: file, line, description, cwe, owasp, severity
- Set `confidence: 0.80` (CodeQL dataflow is reliable but lacks LLM semantic context)
- Set `taint_confirmed: null` (taint-trace will verify it)
- Extract taint path from `codeFlows[]` if present

---

## Step 7 — Write codeql-output.json

```json
{
  "available": true,
  "tool": "codeql",
  "tool_version": "<codeql version output>",
  "repo_path": "<absolute repo path>",
  "generated_at": "<ISO 8601>",
  "languages_analyzed": ["javascript"],
  "query_suite": "javascript-security-extended.qls",
  "codeql_results": {
    "total": 18,
    "confirmed_llm_findings": 14,
    "new_findings": 4
  },
  "new_findings": [
    {
      "id": "CQL-001",
      "codeql_rule": "js/sql-injection",
      "cwe": "CWE-89",
      "owasp": "A03:2021",
      "severity": "critical",
      "confidence": 0.80,
      "file": "routes/login.ts",
      "line": 34,
      "source": "codeql",
      "description": "<CodeQL message.text>",
      "taint_confirmed": null,
      "codeql_signal": "new"
    }
  ],
  "confirmed_findings": ["FINDING-001", "FINDING-002"],
  "db_path": "./codeql-db/"
}
```

---

## Step 8 — Merge into findings.json

1. Load `findings.json`
2. For each confirmed LLM finding: add `codeql_confirmed: true`, `codeql_rule`, `codeql_signal: "confirmed"`
3. Append new `CQL-*` findings to `findings[]`
4. Recalculate `total_findings`
5. Write `findings.json` in place

---

## Step 9 — Print summary

```
codeql-scan complete.
  Repo              : <repo-path>
  Languages         : <list>
  Query suite       : <suite name>
  CodeQL results    : <N> total paths found

  Cross-reference:
    LLM findings confirmed by CodeQL : <N>  (fp_score reduced by 0.25 each)
    New findings CodeQL found alone  : <N>  (added as CQL-* with confidence 0.80)
    Unreachable sinks CodeQL flagged : <N>  (were analyzed by LLM unnecessarily)

  Top new finding types:
    <type> : <N>
    <type> : <N>

  Output: codeql-output.json, findings.json (updated)
```

---

## Constraints

- CodeQL databases can be large (500MB–5GB for big repos). Warn if disk space < 5GB before building.
- Do NOT read source files — CodeQL does the parsing. This skill only invokes CodeQL CLI and processes its JSON/SARIF output.
- If CodeQL is not installed, the pipeline continues normally — this is a pure enhancement layer.
- `CQL-*` findings bypass the `/find-vulns-*` hard constraint (findings from reading code) because CodeQL's dataflow engine IS reading code — just not via LLM. Mark all `CQL-*` findings with `"source": "codeql"` for transparency.
- `/validate-findings` applies the standard `fp_score` rubric to `CQL-*` findings PLUS an additional `-0.25` for `codeql_signal: "confirmed"`.
- CodeQL database is NOT copied to `<out-dir>` (too large). Only `codeql-output.json` is preserved.

## Downstream consumers

- `/validate-findings` — reads `codeql_confirmed` and `codeql_signal` fields to adjust `fp_score`
- `/taint-trace` — `CQL-*` findings with `taint_confirmed: null` are traced normally
- `/scan-report` — includes `codeql_rule` in SARIF `result.properties` for findings where it is set
