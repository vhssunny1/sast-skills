// joern_extract.sc
// Extracts call graph edges and a sink inventory from a CPG.
// Static, checked-in script — previously written fresh by the LLM on every
// run; now byte-identical every invocation, removing that as a source of
// run-to-run non-determinism. Invoked by harness/scripts/joern_parse.py via
// `joern --script joern_extract.sc --param cpgFile=... --param outFile=...`.
//
// A global `params` map (assumed by an earlier draft of this script, going
// off the documented API) does not exist on the installed Joern CLI version
// — confirmed via `joern --help` and a real failing run ("Not found: params").
// This build's actual convention is a top-level `@main def main(...)` whose
// argument names bind to `--param name=value` pairs.
//
// DEGRADED MODE: full source->sink taint-path tracing (reachableByFlows) is
// NOT implemented here. Real, reproducible investigation (see conversation
// history) found that Joern's own `Console.importCpg` — the path the
// builtin `loadCpg()` helper goes through — unconditionally runs a
// JS-frontend post-processing pass (`jssrc2cpg.ObjectPropertyCallLinker`)
// that crashes with `RuntimeException: Assignment statement with 3
// arguments` on real Juice Shop TypeScript code. Confirmed on the latest
// Joern release (v4.0.583) AND an ~8-day-older release (v4.0.579) — not a
// version regression, a persistent bug in Joern's own bundled JS analysis.
// Filed as a known limitation rather than worked around by patching Joern's
// jar. `CpgLoader.load()` (a lower-level API than `loadCpg()`) sidesteps
// that specific crash by skipping the post-processing pass entirely, which
// is why call-graph/sink-inventory extraction below still works — but the
// interprocedural dataflow engine used by reachableByFlows depends on
// passes from that same post-processing stage, so full taint tracing isn't
// available in this degraded mode. find-vulns-* still does its own semantic
// analysis regardless (see CLAUDE.md: "CPG hints guide discovery, never
// replace it") — this only reduces the CPG's pre-population, not coverage.

import java.io._
import io.shiftleft.codepropertygraph.cpgloading.CpgLoader

@main def main(cpgFile: String, outFile: String) = {

// `loadCpg()` (Joern's REPL builtin) routes through Console.importCpg,
// which unconditionally runs the crashing JS post-processing pass — see
// note above. CpgLoader.load() is the lower-level API underneath it and
// skips that pass, confirmed via javap on the actual installed jar.
val cpg = CpgLoader.load(cpgFile)

// ── Sink inventory (pattern-matched, no dataflow engine needed) ────────
val sqlSinks = cpg.call.name("(query|execute|raw|run)").l
val evalSinks = cpg.call.name("(eval|Function|exec|spawn|execFile)").l
val xssSinks  = cpg.call.name("(innerHTML|outerHTML|write|writeln|insertAdjacentHTML|dangerouslySetInnerHTML)").l
val osSinks   = cpg.call.name("(exec|spawn|execSync|spawnSync|execFile)").l
val fsSinks   = cpg.call.name("(readFile|readFileSync|writeFile|writeFileSync|createReadStream|sendFile|render)").l
val fetchSinks = cpg.call.name("(fetch|axios|got|request|http\\.get|https\\.get)").l
val redirectSinks = cpg.call.name("(redirect|location\\.href|location\\.replace|router\\.push)").l

val allSinks = (sqlSinks ++ evalSinks ++ xssSinks ++ osSinks ++ fsSinks ++ fetchSinks ++ redirectSinks).distinct

val sinkInventory = allSinks.map { sink =>
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
  val sinkFile = sink.file.name.headOption.getOrElse("?")
  val sinkLine = sink.lineNumber.getOrElse(-1)
  s"""{"file":"$sinkFile","line":$sinkLine,"sink_name":"${sink.name}","sink_type":"$sinkType"}"""
}

// ── Call graph edges ───────────────────────────────────────────────────
val callEdges = cpg.call
  // Joern models operators (assignment, await, field access, etc.) and
  // imports as synthetic "calls" too, with names like "<operator>.assignment"
  // — confirmed via a real run where these dominated the edge count (36K
  // real edges bloated to 88K once callee names resolved correctly). Real
  // user function calls never start with "<operator>"; excluding those
  // (and the "import" pseudo-call) keeps this graph to genuine call edges,
  // which is what /taint-trace actually wants for caller resolution.
  .filterNot(c => c.name.startsWith("<operator>") || c.name == "import")
  .where(_.callee)
  .map { c =>
    val callerFile   = c.file.name.headOption.getOrElse("?")
    val callerMethod = c.method.name
    val callerLine   = c.lineNumber.getOrElse(-1)
    val calleeFile   = c.callee.file.name.headOption.getOrElse("?")
    // `.callee` is Iterator[Method] (0+ possible callees), so `.name` on it
    // is itself an Iterator[String], not a String — interpolating it
    // directly stringified the iterator object ("<iterator>") rather than
    // the actual name, confirmed via a real test run. `.headOption` picks
    // the first resolved callee's name, matching the calleeFile pattern
    // already used one line above.
    val calleeMethod = c.callee.name.headOption.getOrElse("?")
    s"""{"caller_file":"$callerFile","caller_method":"$callerMethod","caller_line":$callerLine,"callee_file":"$calleeFile","callee_method":"$calleeMethod"}"""
  }.distinct.l

// ── Write output ───────────────────────────────────────────────────────
val json = s"""{
  "degraded": true,
  "degraded_reason": "upstream Joern bug in jssrc2cpg.ObjectPropertyCallLinker (RuntimeException: Assignment statement with 3 arguments) blocks the post-processing passes reachableByFlows needs; confirmed on v4.0.583 and v4.0.579. call_graph and sink inventory below use a lower-level loader that skips that pass, so they are unaffected.",
  "taint_paths": [],
  "sinks_found": [${sinkInventory.mkString(",\n  ")}],
  "call_graph":  [${callEdges.take(2000).mkString(",\n  ")}],
  "unreachable_sinks": [],
  "coverage": {
    "methods_analyzed": ${cpg.method.l.size},
    "calls_analyzed":   ${cpg.call.l.size},
    "sinks_found": ${sinkInventory.size},
    "taint_paths_found": 0,
    "unreachable_sinks": 0
  }
}"""

new PrintWriter(outFile) { write(json); close() }
println(s"CPG extracted (degraded mode): ${sinkInventory.size} sinks found, ${callEdges.size} call edges, 0 taint paths (dataflow engine unavailable — see degraded_reason)")

}
