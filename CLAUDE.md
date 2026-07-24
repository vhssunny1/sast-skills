# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What This Project Is

An LLM-powered SAST pipeline for **polyglot repositories** (Java, Python, TypeScript/React, or any combination) implemented entirely as Claude Code slash commands (`.claude/commands/*.md`). There is no compiled code — the "implementation" is a set of prompt-driven skills that Claude executes in parallel groups where possible, sequentially where dependencies exist. SCA (dependency CVE scanning) is explicitly out of scope.

The pipeline auto-detects languages, routes to the right crawl/find-vulns skills, runs cross-language taint analysis for polyglot repos, and produces SARIF + Markdown reports with CVSS 3.1 scores per finding.

## Running a Scan

Full pipeline against any repo:
```
/sast-full-scan <repo-path>
/sast-full-scan <repo-path> --ground-truth <ground-truth.md>   # with precision/recall
/sast-full-scan <repo-path> --dast                              # also generate DAST test script
```

Via the Python harness (`harness/cli.py` / `harness/pipeline.py`) — see `harness/README.md`:
```
python3 cli.py <repo-path> --recheck-tier5   # re-scan security_priority:5 files a second time
```
`--recheck-tier5` is a harness-only flag (not yet in `/sast-full-scan`'s markdown orchestrator — see the "two orchestrators" note below). After the normal find-vulns pass, it re-scans just the `security_priority: 5` files once more with a fresh LLM read, merging any new findings via the same dedup path as ordinary batches. Real Juice Shop test (run `20260724-150206`, 28 tier-5 files): $1.11 extra recovered all 5 baseline findings and caught 2 genuinely new ones in `routes/fileUpload.ts` that the first pass missed — a targeted, much cheaper alternative to re-running the whole find-vulns stage 2-3x (~$6-12).

Individual skills can be invoked independently:
```
/detect-language <repo-path>
/crawl-python <repo-path>
/crawl-typescript <repo-path>
/config-audit <repo-path>
/find-vulns-python --crawl crawl-output.json
/find-vulns-typescript --crawl crawl-output.json
/find-vulns-java --crawl crawl-output.json
/cross-language-taint --findings findings.json --crawl crawl-output.json
/taint-trace --findings findings.json --crawl crawl-output.json
/validate-findings --findings findings.json
/scan-report --findings findings.json
/generate-fix FINDING-001
/scan-metrics --run-dir sast-runs/<timestamp>/
```

## Pipeline Architecture

`/sast-full-scan` (or the harness `cli.py`/`pipeline.py`) runs two pre-steps then three execution groups:

```
/detect-language     → language-manifest.json

/crawl-tree-sitter   → crawl-output.json          DETERMINISTIC SCRIPT (harness/scripts/crawl_tree_sitter.py) —
                       not an LLM step. Real tree-sitter AST parse + real code classification.
                       Byte-identical output on repeated runs. Supersedes crawl-python/typescript/java
                       in Group 1 when it succeeds; falls back to them transparently otherwise.
                       Pass --skip-tree-sitter to bypass.

/joern-parse         → cpg-output.json            DETERMINISTIC SCRIPT (harness/scripts/joern_parse.py +
                       joern_extract.sc) — not an LLM step. Runs in DEGRADED MODE: full source→sink
                       taint tracing is blocked by an upstream Joern bug (see joern_extract.sc's header
                       comment) — cpg-output.json carries "degraded": true, "taint_paths": [] and
                       "unreachable_sinks": [] when this applies. call_graph[] and the new sinks_found[]
                       (sink locations, no traced source) are unaffected and fully populated.
                       find-vulns skills use whichever of taint_paths[]/sinks_found[] is non-empty to
                       prioritize files and pre-confirm chains. Pass --skip-joern to bypass.

── GROUP 1 (concurrent) ──────────────────────────────────────────────
/crawl-python       → crawl-output-python.json   (fallback only — skipped if crawl-tree-sitter ran)
/crawl-typescript   → crawl-output-typescript.json (fallback only — skipped if crawl-tree-sitter ran)
/config-audit       → findings.json (appended)   (reads .env, docker-compose, Dockerfiles, CI)
                    [merge crawl outputs → crawl-output.json]

── GROUP 2 (concurrent across languages, sequential within — batched) ─
/find-vulns-python  → findings-python.json        (loads cpg-output.json → CPG-guided + LLM discovery)
/find-vulns-typescript → findings-typescript.json (loads cpg-output.json → CPG-guided + LLM discovery)
/find-vulns-java    → findings-java.json          (loads cpg-output.json → CPG-guided + LLM discovery)
/codeql-scan        → codeql-output.json          (optional — pass --codeql; confirms/augments findings)
  [harness only] --recheck-tier5 : after the normal batches, re-scans just security_priority:5 files
  once more (fresh LLM read) as one extra batch — cheap, targeted recovery of run-to-run misses.
  Real test: $1.11 recovered all baseline findings + 2 new ones, vs ~$6-12 for a full 2-3x re-run.
                    [merge all findings → findings.json]

── GROUP 3 (sequential) ──────────────────────────────────────────────
/cross-language-taint → findings.json (appended) (polyglot only — XL-* prefix findings)
/taint-trace        → findings.json (enriched; loads call_graph[] from cpg-output.json via --cpg to
                       resolve callers without re-reading files — falls back to manually reading every
                       entry-point file only when CPG data is unavailable or a specific callee isn't covered)
/validate-findings  → findings.json (enriched; codeql_confirmed → -0.25, cpg_guided+cpg_source_confirmed
                       → -0.15/-0.05 fp_score adjustments)
/scan-report        → scan-results.sarif + scan-summary.md (CVSS + cpg_guided/codeql_confirmed in both)
```

Supporting skills (run standalone or after full scan):
```
/scan-metrics       → sast-metrics.json (append-only; reads run-log.json for step_timings + token/cost)
/generate-fix       → diff + explanation (standalone, reads findings.json)
/generate-dast-tests → dast-tests.py (optional — requires --dast flag)
```

`/sast-full-scan` writes intermediate snapshots to `sast-runs/<timestamp>/`, including a `run-log.json` with per-step timing, token/cost usage, findings delta, and error capture. **Note:** `/sast-full-scan` (the markdown orchestrator) and `harness/pipeline.py` (the Python orchestrator) are two independent implementations of this same flow — see the constraint below.

## Key Files

| File | Purpose |
|---|---|
| `language-manifest.json` | Output of `/detect-language` — routes pipeline to correct skills |
| `cpg-output.json` | Joern CPG export — call graph edges + sink inventory (`sinks_found[]`). Available when Joern is installed; stub with `available:false` otherwise. Currently `degraded: true` — `taint_paths[]`/`unreachable_sinks[]` are always empty due to an upstream Joern bug (see Skill Contracts). |
| `codeql-output.json` | CodeQL SARIF cross-reference — confirmed LLM findings + new CQL-* findings. Written only when `--codeql` passed. |
| `crawl-output.json` | Merged crawl output (polyglot: merged from `crawl-output-<lang>.json` after Group 1) |
| `findings.json` | Live findings file — progressively enriched by config-audit, find-vulns (CPG-guided + LLM), codeql-scan, cross-language-taint, taint-trace, validate-findings. Each finding includes `cvss_vector`, `cvss_score`, `cpg_guided`, and optionally `codeql_confirmed`. |
| `scan-results.sarif` | SARIF 2.1.0 output for IDE/GitHub Security tab — includes `cvss_vector`/`cvss_score` in `result.properties` |
| `scan-summary.md` | Human-readable Markdown report with fixes — includes CVSS per finding and score range in summary |
| `sast-metrics.json` | Append-only metrics history across scan runs — includes `step_timings[]` from `run-log.json` |
| `run-log.json` | Structured per-step audit log written by `/sast-full-scan` — timing, findings delta, errors per step |
| `sast-runs/<timestamp>/` | Immutable snapshot of every intermediate artifact per full-scan run |
| `dast-tests.py` | Generated DAST test script (only when `--dast` passed) |

## Skill Contracts

Each skill in `.claude/commands/` has a strict input/output contract. When modifying a skill:

- **`/detect-language`** — takes `<repo-path>`, writes `language-manifest.json`. Determines significant languages and routes to the correct crawl/find-vulns skills. Never reads source files — only counts extensions and reads package manifests.
- **`/joern-parse`** — takes `<repo-path>` + `language-manifest.json`, writes `cpg-output.json`. Delegates to `harness/scripts/joern_parse.py` + the checked-in `harness/scripts/joern_extract.sc` query — a deterministic script, not an LLM analysis step (converted from an LLM-driven skill; see below). Runs Joern to build a CPG and exports call graph + a sink inventory. Runs automatically if Joern is installed; skips gracefully with `available:false` stub otherwise. Never reads source files directly — Joern parses the repo. **Currently runs in degraded mode** — `taint_paths[]`/`unreachable_sinks[]` are always empty (`degraded: true` + `degraded_reason` set) because full dataflow tracing (`reachableByFlows`) is blocked by an upstream Joern bug (confirmed on v4.0.583 and v4.0.579 — not a version regression). `sinks_found[]` and `call_graph[]` are unaffected and still real/deterministic. See `joern_extract.sc`'s header comment for the full investigation and what to restore if upstream ever fixes it.
- **`/crawl-tree-sitter`** — takes `<repo-path>` + `language-manifest.json`, writes `crawl-output.json`. Delegates to `harness/scripts/crawl_tree_sitter.py` — a deterministic script, not an LLM analysis step. Runs `tree-sitter parse -x` per file and classifies role/`security_priority` from real AST traversal (not LLM interpretation of the AST text). Supersedes crawl-python/crawl-typescript/crawl-java in Group 1 when tree-sitter is available; falls back transparently otherwise.
- **`/crawl-python`** — takes `<repo-path>`, writes `crawl-output.json`. Classifies Python files by role (`entry_point`, `middleware`, `async_worker`, `dao`, `model`, `service`, `config`, `util`). Assigns `security_priority` scores. Fallback for when tree-sitter is unavailable — `/crawl-tree-sitter` supersedes this when it can run.
- **`/crawl-typescript`** — takes `<repo-path>`, writes `crawl-output.json`. Classifies TypeScript/React files by role (`entry_point`, `middleware`, `service`, `dao`, `model`, `component`, `config`, `util`). Fallback for when tree-sitter is unavailable — `/crawl-tree-sitter` supersedes this when it can run.
- **`/config-audit`** — takes `<repo-path>`, appends to `findings.json`. Reads `.env`, `docker-compose.yml`, `Dockerfile*`, CI files, `settings.py`, `constants.py`, `.cfg`/`.conf` files. Never reads application source code. Outputs `cvss_vector` and `cvss_score` on every finding. Runs in Group 1 concurrently with crawl skills.
- **`/find-vulns-python`** — takes `crawl-output.json` + optional `cpg-output.json`, writes `findings-python.json`. Loads CPG taint hints (Step 1.5) if available: boosts file priorities, pre-populates CPG candidates, uses call graph for caller resolution. Confirms CPG candidates via LLM file read. Still runs full LLM discovery for paths CPG may have missed. Hard constraint: findings come from reading the code.
- **`/find-vulns-typescript`** — same as find-vulns-python with TypeScript-specific sources/sinks. Writes `findings-typescript.json`.
- **`/find-vulns-java`** — same CPG integration as above with Java-specific patterns (Struts2/Spring). Writes `findings-java.json`.
- **`/codeql-scan`** — optional (`--codeql` flag). Takes `<repo-path>` + `language-manifest.json`. Runs CodeQL CLI in parallel with find-vulns (Group 2). Cross-references CodeQL SARIF against LLM findings: confirmed findings get `codeql_confirmed: true` + `-0.25 fp_score`. New CodeQL-only findings added as `CQL-*`. Skips gracefully if CodeQL CLI not installed.
- **`/cross-language-taint`** — takes `findings.json` + `crawl-output.json`, appends `XL-*` findings. Matches Python backend store points against TypeScript frontend render points. Also detects multi-hop prompt injection via RAG retrieval. Requires `language_boundary` on every XL finding.
- **`/taint-trace`** — enriches each finding with `taint_confirmed`, `confidence_after_trace`, `taint_path[]`, and `sanitization_gaps[]`. Uses `call_graph[]` from `cpg-output.json` to resolve callers without re-reading files. Does NOT add new findings.
- **`/validate-findings`** — adds `fp_score` and `validation_status` (`confirmed` / `likely_real` / `needs_review` / `likely_fp`). Applies `-0.25 fp_score` for `codeql_confirmed: true` findings. Sorts by severity → `cvss_score` DESC → `fp_score` ASC → `confidence_after_trace` DESC. Works only from `findings.json` — never reads source code. XL findings are never deduplicated against intra-language findings.
- **`/scan-report`** — produces SARIF 2.1.0 (`scan-results.sarif`) and Markdown summary (`scan-summary.md`). Includes `cvss_vector`/`cvss_score`/`cpg_guided`/`codeql_confirmed` in SARIF `result.properties`. Computes precision/recall when `--ground-truth` is provided.
- **`/generate-fix`** — takes a single `finding-id`, reads the vulnerable file, outputs a unified diff + explanation + test cases. One finding per invocation.
- **`/generate-dast-tests`** — takes `findings.json`, outputs `dast-tests.py` — a runnable behavioral test script for dynamic verification against a live app. Run only when `--dast` is passed to `/sast-full-scan`.
- **`/scan-metrics`** — reads run artifacts from `sast-runs/<timestamp>/` including `run-log.json`. Extracts `step_timings[]` (duration, findings delta, errors per step) and appends a full metrics record to `sast-metrics.json`.

## Finding ID Prefixes

| Prefix | Skill | Meaning |
|---|---|---|
| `CONFIG-*` | `/config-audit` | Configuration / deployment finding |
| `PY-*` | `/find-vulns-python` | Python source finding |
| `TS-*` | `/find-vulns-typescript` | TypeScript/React source finding |
| `JAVA-*` | `/find-vulns-java` | Java source finding |
| `XL-*` | `/cross-language-taint` | Cross-language taint path (requires `language_boundary`) |
| `CQL-*` | `/codeql-scan` | CodeQL-only finding (no LLM match found; LLM confirmation via taint-trace) |

## Important Constraints

- **Two orchestrators exist and are not fully in sync — a known, open decision, not an oversight.** `/sast-full-scan` (736-line markdown skill, LLM-executed turn-by-turn) and `harness/pipeline.py` (Python, deterministic) both implement this same flow independently. `pipeline.py`'s own docstring says "replaces sast-full-scan.md," but the markdown version is still present and runnable, and only `pipeline.py` has the crawl-tree-sitter/joern-parse script conversion and `--recheck-tier5`. Anyone running `/sast-full-scan` standalone gets the older, fully LLM-driven orchestration path. Do not silently let this drift further — either bring `sast-full-scan.md` to parity when changing `pipeline.py`, or (the maintainer's call, not yet made) deprecate it in favor of the harness being the only supported entry point.
- **Skills must be flat in `.claude/commands/`** — subdirectories are not recognized by Claude Code.
- **The repo needs `.git`** — Claude Code requires a git repository to discover project-level slash commands.
- **No pattern-matching against ground truth in `/find-vulns-*`** — findings must come from reading the code. Using a ground truth file as a lookup table is a correctness violation.
- **`/config-audit` never reads source code** — only configuration files. Speculation requiring source knowledge goes in `fix_hint`, not `description`.
- **XL findings require both sides** — `/cross-language-taint` must cite a `language_boundary` with backend file+line AND frontend file+line. Never create an XL finding with only one side confirmed.
- **CPG hints guide discovery, never replace it** — `cpg-output.json` boosts file priorities and pre-populates candidates, but `/find-vulns-*` skills must still read source files to confirm every candidate. A CPG path without LLM confirmation does NOT become a finding. This preserves the semantic accuracy of LLM analysis while gaining the graph's coverage completeness. **Note:** while `/joern-parse` runs in degraded mode (see above), `taint_paths[]` is always empty, so this pre-population currently comes from `sinks_found[]` (sink locations, no traced source) and `call_graph[]` only — `find-vulns-*` skills reading `cpg-output.json` should treat a `degraded: true` flag as "no pre-confirmed candidates available, fall back fully to LLM discovery for taint tracing," not as an error.
- **`/joern-parse` and `/codeql-scan` never read source files directly** — Joern and CodeQL parse the repo themselves. These skills only invoke the tools and process their output JSON/SARIF. The LLM-reads-code constraint applies only to find-vulns-* skills.
- **`/crawl-tree-sitter` and `/joern-parse` are deterministic scripts, not LLM steps** — both were originally LLM-driven (the LLM ran `tree-sitter parse -x`/Joern itself and interpreted the output turn-by-turn), which caused real run-to-run drift on an *unchanged* repo: file counts (394/356/395), batch counts, and which bugs got flagged varied between otherwise-identical scans. Both now delegate to checked-in Python (`harness/scripts/crawl_tree_sitter.py`, `harness/scripts/joern_parse.py` + `joern_extract.sc`), invoked directly by `pipeline.py`'s `script_step()` (bypassing `claude --print` entirely) in the automated harness, or via Bash by the LLM when run interactively as a slash command. Either path produces byte-identical output for byte-identical input — do not "improve" a classification by re-reading files and overriding the script's output; fix the script instead.
- **`CQL-*` findings bypass the find-vulns-from-code constraint** — CodeQL's dataflow engine read the code; the finding is legitimate. All CQL-* findings must still pass through `/taint-trace` for LLM semantic confirmation before being trusted.
- **Statelessness is intentional** — skills share no in-memory state. All cross-skill communication is through files (`crawl-output.json`, `cpg-output.json`, `codeql-output.json`, `findings.json`, `language-manifest.json`, `run-log.json`). This is a design choice, not a limitation — it enables parallel group execution without shared state.
- **Parallel groups require file-naming discipline** — when multiple crawl or find-vulns skills run in the same group, the orchestrator renames each skill's output to a language-specific file (`crawl-output-python.json`, `findings-typescript.json`) before the next skill runs, then merges after the group completes. Do not assume `crawl-output.json` or `findings.json` are the live outputs mid-group.
- **CVSS scores must be consistent with severity** — Critical findings must have `cvss_score` 9.0–10.0, High 7.0–8.9, Medium 4.0–6.9, Low 0.1–3.9. Mismatches between the label and the numeric score are a correctness violation.
- **Scan outputs are gitignored** — `findings.json`, `sast-runs/`, HTML reports, `crawl-output.json`, `scan-results.sarif`, and `dast-tests.py` are all excluded from version control. Only `.claude/commands/*.md`, `CLAUDE.md`, and `README.md` are committed.
- **`/find-vulns-*` coverage completeness is required** — every file with `security_priority` ≥ 2 in the crawl manifest must receive at least one full read/analysis pass. Silent truncation at tier boundaries is a correctness violation. Track `files_attempted` vs `files_in_manifest` in the findings output.
- **XL-PI-* findings do not require a frontend render sink** — standalone prompt injection findings fire when attacker-controlled content reaches LLM context without a trust boundary, even if there is no downstream `innerHTML`/XSS sink. `/cross-language-taint` is responsible for both XL (stored-XSS) and XL-PI (prompt injection) classes.
- **Explicitly out of scope — business logic bugs:** TOCTOU races, wrong exception-swallowing (broad `except` that silently drops a guard), incorrect migration ordering, wrong success-marking in state machines, and similar logic-correctness defects have no source→sink shape and are not modeled by any current skill. These are accepted gaps, not oversights. A future `logic-audit` skill could cover them if the team prioritizes it.
- **Explicitly out of scope — SCA/dependency CVE scanning:** Known CVEs in third-party packages are not reported. The pipeline focuses on first-party code vulnerabilities and configuration mistakes.
