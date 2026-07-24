Build a Code Property Graph (CPG) from the target repository using Joern and export a machine-readable taint edge + call graph summary that downstream find-vulns skills consume.

This skill runs AFTER detect-language and BEFORE Group 1 crawl. It provides exhaustive graph coverage so find-vulns skills do not miss taint paths that require following chains across many files. The LLM still reads source files for semantic confirmation in find-vulns-* — the CPG provides the roadmap.

**This skill is a deterministic script, not an LLM analysis step.** Locating the Joern binary, building the CPG, running the taint-extraction query, and relaying its JSON output were always mechanical operations — the only thing that varied was the LLM re-writing the query script fresh each run. The query script is now `harness/scripts/joern_extract.sc`, checked into the repo (byte-identical every invocation), and `harness/scripts/joern_parse.py` runs the whole sequence as real code.

## Your job

1. Run:
   ```bash
   python3 harness/scripts/joern_parse.py <repo-path> --manifest language-manifest.json --cpg-out cpg-output.json
   ```
   (paths relative to your working directory; use absolute paths if unsure). If `harness/scripts/joern_parse.py` is not found relative to the current directory, locate it under the repo root's `harness/scripts/` and use that path instead. Pass `--joern-bin <path>` if Joern isn't on `$PATH`.
2. Read the resulting `cpg-output.json` and relay/summarize it.
3. Print the script's own stdout summary verbatim (taint paths found, call graph edges, unreachable sinks, top sink types) — do not recompute these from the JSON yourself.

## Input

`$ARGUMENTS` format: `<repo-path> --manifest language-manifest.json [--cpg-out <path>] [--joern-bin <path>]`

- `<repo-path>` — required. Absolute path to the repository to analyze.
- `--manifest <path>` — path to `language-manifest.json` (default: `./language-manifest.json`)
- `--cpg-out <path>` — where to write `cpg-output.json` (default: `./cpg-output.json`)
- `--joern-bin <path>` — path to Joern installation (default: auto-detect from `$PATH` and common install locations)

Pass these through to the script unchanged.

## If Joern is not installed / not supported for this language

The script itself detects this and writes a stub to the output path, then exits 0 — do not treat this as a failure:
```json
{ "available": false, "reason": "joern_not_installed", "repo_path": "<repo-path>", "generated_at": "<ISO 8601>" }
```
Relay its printed message:
```
joern-parse: Joern not installed — CPG analysis skipped.
  Install: https://docs.joern.io/installation
  Effect : find-vulns will operate without CPG taint hints (current behavior).
  To suppress this warning: pass --skip-joern to sast-full-scan.
```

## Output schema (cpg-output.json)

```json
{
  "available": true,
  "tool": "joern",
  "tool_version": "<joern --version output>",
  "repo_path": "<absolute repo path>",
  "generated_at": "<ISO 8601>",
  "languages_analyzed": ["typescript"],
  "degraded": true,
  "degraded_reason": "upstream Joern bug in jssrc2cpg.ObjectPropertyCallLinker ... blocks the post-processing passes reachableByFlows needs; confirmed on v4.0.583 and v4.0.579.",
  "taint_paths": [],
  "sinks_found": [
    { "file": "routes/login.ts", "line": 34, "sink_name": "query", "sink_type": "sql_injection" }
  ],
  "call_graph": [
    { "caller_file": "routes/login.ts", "caller_method": "router.post./login", "caller_line": 10,
      "callee_file": "lib/insecurity.ts", "callee_method": "hash" }
  ],
  "unreachable_sinks": [],
  "coverage": { "methods_analyzed": 1250, "calls_analyzed": 4800, "sinks_found": 23, "taint_paths_found": 0, "unreachable_sinks": 0 }
}
```

**Currently running in degraded mode** (see Constraints) — `taint_paths[]` and `unreachable_sinks[]` are always empty and `degraded: true` is set, because full interprocedural dataflow tracing (`reachableByFlows`) is blocked by an upstream Joern bug (see below). `sinks_found[]` is the replacement signal: real sink locations from the CPG (no hop-by-hop path, no source correlation), still useful for `find-vulns-*` to prioritize which files/lines to check. If a future Joern release fixes the underlying bug, `joern_extract.sc` can be reverted to use `reachableByFlows` for full taint-path tracing again — see the script's own header comment for exactly what to restore.

`call_graph[]` is capped at 2000 edges. Polyglot repos: the script runs Joern once per distinct language flag and merges `taint_paths`/`call_graph`/`unreachable_sinks`/`sinks_found` (deduplicated) with summed `coverage`, matching the schema above exactly.

## Constraints

- Do not re-run or hand-modify the Joern query — `harness/scripts/joern_extract.sc` is the single source of truth for the taint/call-graph extraction logic. If it needs to change, that's an edit to the checked-in script, not a per-run improvisation.
- **Full taint-path tracing is disabled (degraded mode) — this is deliberate, not a bug to silently "fix" by re-adding `reachableByFlows` calls.** Real investigation (see script header comment and project history) found that Joern's own `loadCpg()` builtin (which routes through `Console.importCpg`) unconditionally runs a JS-frontend post-processing pass (`jssrc2cpg.ObjectPropertyCallLinker`) that crashes with `RuntimeException: Assignment statement with 3 arguments` on real-world TypeScript code — confirmed on the latest Joern release (v4.0.583) and an ~8-day-older release (v4.0.579), so it's a persistent upstream bug, not a version regression fixable by pinning elsewhere. The script works around it by loading the CPG via the lower-level `io.shiftleft.codepropertygraph.cpgloading.CpgLoader.load()` API instead, which skips that crashing pass — but the dataflow engine's own passes are part of the same post-processing stage, so `reachableByFlows` isn't usable in this mode. Do not attempt to re-enable it without first confirming upstream has actually fixed this crash.
- Joern CPG binaries are NOT copied to `<out-dir>` (too large) — only `cpg-output.json` is preserved.
- `unreachable_sinks` is always empty in degraded mode (computing it requires the same blocked dataflow engine) — this is not the same as "no unreachable sinks exist," it means the check wasn't run.

## Downstream consumers

- `/find-vulns-typescript`, `/find-vulns-python`, `/find-vulns-java` — read `cpg-output.json` at Step 1.5 to load taint hints before building the scan queue
- `/taint-trace` — can use `call_graph[]` to resolve callers without re-reading files
- `/cross-language-taint` — `taint_paths[]` spanning two language files are flagged as cross-language candidates
