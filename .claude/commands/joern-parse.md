Build a Code Property Graph (CPG) from the target repository using Joern and export a machine-readable taint edge + call graph summary that downstream find-vulns skills consume.

This skill runs AFTER detect-language and BEFORE Group 1 crawl. It provides exhaustive graph coverage so find-vulns skills do not miss taint paths that require following chains across many files. The LLM still reads source files for semantic confirmation — the CPG provides the roadmap.

## Input

`$ARGUMENTS` format: `<repo-path> --manifest language-manifest.json [--cpg-out <path>] [--joern-bin <path>]`

- `<repo-path>` — required. Absolute path to the repository to analyze.
- `--manifest <path>` — path to `language-manifest.json` (default: `./language-manifest.json`)
- `--cpg-out <path>` — where to write `cpg-output.json` (default: `./cpg-output.json`)
- `--joern-bin <path>` — path to Joern installation (default: auto-detect from `$PATH` and common install locations)

---

## Step 1 — Detect Joern installation

Check for Joern in this order:

1. `$JOERN_HOME/bin/joern` if `$JOERN_HOME` is set
2. `joern` on `$PATH` (run `joern --version`)
3. `~/.local/share/joern/joern-cli/joern`
4. `/opt/joern/joern-cli/joern`
5. Value of `--joern-bin` flag

If Joern is not found:
```
joern-parse: Joern not installed — CPG analysis skipped.
  Install: https://docs.joern.io/installation
  Effect : find-vulns will operate without CPG taint hints (current behavior).
  To suppress this warning: pass --skip-joern to sast-full-scan.
```

Write a **stub** `cpg-output.json` with `"available": false` so downstream skills know CPG was attempted but unavailable:
```json
{
  "available": false,
  "reason": "joern_not_installed",
  "repo_path": "<repo-path>",
  "generated_at": "<ISO 8601>"
}
```
Stop — do not error. The pipeline continues without CPG.

---

## Step 2 — Determine language scope

Read `language-manifest.json`. Extract `languages[]` and `primary_language`.

Map to Joern language flags:

| Language | Joern flag |
|---|---|
| `typescript` or `javascript` | `--language javascript` |
| `python` | `--language python` |
| `java` or `kotlin` | `--language java` |
| Polyglot | Run Joern once per language; merge outputs |

If language is not supported by Joern (Go, Ruby, C#), write stub with `"reason": "language_not_supported"` and stop.

---

## Step 3 — Build CPG database

For each language in scope, run:

```bash
joern-parse <repo-path> \
  --language <joern-lang-flag> \
  --output ./joern-cpg-<language>.bin \
  --exclude-regex "node_modules|dist|build|__pycache__|\.venv|test|spec|\.git"
```

If `joern-parse` exits non-zero:
- Log the error message
- Write stub with `"reason": "parse_failed"`, `"error": "<stderr output>"`
- Stop — pipeline continues without CPG

Expected output: `./joern-cpg-<language>.bin` — binary CPG database.

---

## Step 4 — Extract taint paths

For each CPG database, run the Joern query script below via:
```bash
joern --script joern-extract.sc \
      --params "cpgFile=./joern-cpg-<language>.bin,outFile=./cpg-paths-<language>.json"
```

**`joern-extract.sc` content** — write this script to disk before executing:

```scala
// joern-extract.sc
// Extracts taint paths, call graph edges, and unreachable sinks from a CPG.

import java.io._
import scala.util.Try

val cpgFile = params("cpgFile")
val outFile = params("outFile")

val cpg = loadCpg(cpgFile)

// ── Taint sources ──────────────────────────────────────────────────────
val httpSources = cpg.call
  .name("(get|post|put|delete|patch)")
  .where(_.argument.code("req\\.(body|query|params|headers|cookies).*"))
  .l

val paramSources = cpg.identifier
  .where(_.code("req\\.(body|query|params|headers).*"))
  .l

// ── Taint sinks ────────────────────────────────────────────────────────
val sqlSinks = cpg.call
  .name("(query|execute|raw|run)")
  .where(_.argument.isCallTo(".*"))
  .l

val evalSinks = cpg.call.name("(eval|Function|exec|spawn|execFile)").l
val xssSinks  = cpg.call.name("(innerHTML|outerHTML|write|writeln|insertAdjacentHTML|dangerouslySetInnerHTML)").l
val osSinks   = cpg.call.name("(exec|spawn|execSync|spawnSync|execFile)").l
val fsSinks   = cpg.call.name("(readFile|readFileSync|writeFile|writeFileSync|createReadStream|sendFile|render)").l
val fetchSinks = cpg.call.name("(fetch|axios|got|request|http\\.get|https\\.get)").l
val redirectSinks = cpg.call.name("(redirect|location\\.href|location\\.replace|router\\.push)").l

val allSinks = (sqlSinks ++ evalSinks ++ xssSinks ++ osSinks ++ fsSinks ++ fetchSinks ++ redirectSinks).distinct

// ── Trace taint paths ──────────────────────────────────────────────────
val taintPaths = allSinks.flatMap { sink =>
  val flows = sink.reachableByFlows(cpg.parameter.l ++ paramSources).l
  flows.zipWithIndex.map { case (flow, i) =>
    val steps = flow.elements.map { node =>
      s"""{"file":"${node.file.name.headOption.getOrElse("?")}","line":${node.lineNumber.getOrElse(-1)},"code":"${node.code.replace("\"","\\\"").take(120)}"}"""
    }.mkString("[", ",", "]")
    val sinkType = sink.name match {
      case n if sqlSinks.contains(sink)      => "sql_injection"
      case n if evalSinks.contains(sink)     => "code_injection"
      case n if xssSinks.contains(sink)      => "xss"
      case n if osSinks.contains(sink)       => "command_injection"
      case n if fsSinks.contains(sink)       => "path_traversal"
      case n if fetchSinks.contains(sink)    => "ssrf"
      case n if redirectSinks.contains(sink) => "open_redirect"
      case _                                 => "unknown"
    }
    val sourceFile = flow.elements.head.file.name.headOption.getOrElse("?")
    val sourceLine = flow.elements.head.lineNumber.getOrElse(-1)
    val sinkFile   = sink.file.name.headOption.getOrElse("?")
    val sinkLine   = sink.lineNumber.getOrElse(-1)
    s"""{"source_file":"$sourceFile","source_line":$sourceLine,"sink_file":"$sinkFile","sink_line":$sinkLine,"sink_name":"${sink.name}","sink_type":"$sinkType","hop_count":${flow.elements.size},"steps":$steps}"""
  }
}

// ── Call graph edges ───────────────────────────────────────────────────
val callEdges = cpg.call
  .where(_.callee.isDefined)
  .map { c =>
    val callerFile   = c.file.name.headOption.getOrElse("?")
    val callerMethod = c.method.name
    val callerLine   = c.lineNumber.getOrElse(-1)
    val calleeFile   = c.callee.file.name.headOption.getOrElse("?")
    val calleeMethod = c.callee.name
    s"""{"caller_file":"$callerFile","caller_method":"$callerMethod","caller_line":$callerLine,"callee_file":"$calleeFile","callee_method":"$calleeMethod"}"""
  }.distinct.l

// ── Unreachable sinks (dead code / no caller path) ─────────────────────
val reachableSinkFiles = taintPaths.map(p => p).toSet
val unreachable = allSinks.filter { sink =>
  sink.reachableByFlows(cpg.parameter.l).isEmpty
}.map { sink =>
  s"""{"file":"${sink.file.name.headOption.getOrElse("?")}","line":${sink.lineNumber.getOrElse(-1)},"sink_name":"${sink.name}"}"""
}

// ── Write output ───────────────────────────────────────────────────────
val json = s"""{
  "taint_paths": [${taintPaths.mkString(",\n  ")}],
  "call_graph":  [${callEdges.take(2000).mkString(",\n  ")}],
  "unreachable_sinks": [${unreachable.mkString(",\n  ")}],
  "coverage": {
    "methods_analyzed": ${cpg.method.l.size},
    "calls_analyzed":   ${cpg.call.l.size},
    "taint_paths_found": ${taintPaths.size},
    "unreachable_sinks": ${unreachable.size}
  }
}"""

new PrintWriter(outFile) { write(json); close() }
println(s"CPG extracted: ${taintPaths.size} taint paths, ${callEdges.size} call edges")
```

If the Joern script exits non-zero, log the error but continue — write partial output if any paths were found.

---

## Step 5 — Merge multi-language outputs (polyglot only)

If multiple `cpg-paths-<language>.json` files were produced:
1. Read all files
2. Combine `taint_paths[]` arrays (deduplicate by `source_file + source_line + sink_file + sink_line`)
3. Combine `call_graph[]` arrays (deduplicate by `caller_file + caller_method + callee_file + callee_method`)
4. Combine `unreachable_sinks[]`
5. Sum `coverage` fields

---

## Step 6 — Write cpg-output.json

Write to `--cpg-out` path (default: `./cpg-output.json`):

```json
{
  "available": true,
  "tool": "joern",
  "tool_version": "<joern --version output>",
  "repo_path": "<absolute repo path>",
  "generated_at": "<ISO 8601>",
  "languages_analyzed": ["typescript"],
  "taint_paths": [
    {
      "source_file": "routes/login.ts",
      "source_line": 12,
      "sink_file": "routes/login.ts",
      "sink_line": 34,
      "sink_name": "query",
      "sink_type": "sql_injection",
      "hop_count": 1,
      "steps": [
        { "file": "routes/login.ts", "line": 12, "code": "req.body.email" },
        { "file": "routes/login.ts", "line": 34, "code": "sequelize.query(`SELECT...${email}...`)" }
      ]
    }
  ],
  "call_graph": [
    {
      "caller_file": "routes/login.ts",
      "caller_method": "router.post./login",
      "caller_line": 10,
      "callee_file": "lib/insecurity.ts",
      "callee_method": "hash"
    }
  ],
  "unreachable_sinks": [
    { "file": "lib/legacy.ts", "line": 44, "sink_name": "eval" }
  ],
  "coverage": {
    "methods_analyzed": 1250,
    "calls_analyzed": 4800,
    "taint_paths_found": 23,
    "unreachable_sinks": 2
  }
}
```

---

## Step 7 — Print summary

```
joern-parse complete.
  Repo              : <repo-path>
  Languages parsed  : <list>
  Taint paths found : <N>  (exhaustive — includes all graph-reachable paths)
  Call graph edges  : <N>
  Unreachable sinks : <N>  (dead code — find-vulns will skip these)
  Output            : cpg-output.json

  Top sink types:
    sql_injection    : <N> paths
    xss              : <N> paths
    code_injection   : <N> paths
    command_injection: <N> paths
    ssrf             : <N> paths
    open_redirect    : <N> paths

  find-vulns skills will use these paths to:
    (1) Prioritize which files to read first (highest-hit files)
    (2) Pre-confirm paths without re-tracing each hop
    (3) Reduce analysis time on already-mapped taint chains
```

---

## Constraints

- Do NOT read source files — Joern parses the repo. This skill only invokes Joern and processes its output.
- If Joern is not installed, the pipeline continues in degraded mode — do not error or stop the full scan.
- `call_graph[]` is capped at 2000 edges in the export to keep file sizes manageable. The full CPG database is retained on disk for interactive queries.
- Joern CPG binary is NOT copied to `<out-dir>` (too large). Only `cpg-output.json` is preserved.
- `unreachable_sinks` is informational — find-vulns still reads those files but deprioritizes them.

## Downstream consumers

- `/find-vulns-typescript`, `/find-vulns-python`, `/find-vulns-java` — read `cpg-output.json` at Step 1.5 to load taint hints before building the scan queue
- `/taint-trace` — can use `call_graph[]` to resolve callers without re-reading files
- `/cross-language-taint` — `taint_paths[]` spanning two language files are flagged as cross-language candidates
