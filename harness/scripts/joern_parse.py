"""
Deterministic replacement for the LLM-driven /joern-parse skill.

Everything this skill does is already mechanical — locate the Joern binary,
run `joern-parse` to build a CPG, run a fixed query script against it, relay
the resulting JSON. The only non-determinism the LLM version had was writing
`joern-extract.sc` fresh each run; that script is now `joern_extract.sc`,
checked into the repo alongside this file, so it's byte-identical every time.

Output schema matches .claude/commands/joern-parse.md's cpg-output.json
exactly, so no downstream skill (find-vulns-*, taint-trace, cross-language-
taint) needs to change.
"""

import argparse
import json
import os
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

LANG_FLAGS = {
    "typescript": "javascript",
    "javascript": "javascript",
    "python": "python",
    "java": "java",
    "kotlin": "java",
}
UNSUPPORTED = {"go", "ruby", "csharp", "c#"}

SCRIPT_DIR = Path(__file__).resolve().parent


def find_joern_bin(explicit: Optional[str]) -> Optional[str]:
    if explicit:
        return explicit
    home = os.environ.get("JOERN_HOME")
    if home and (Path(home) / "bin" / "joern").exists():
        return str(Path(home) / "bin" / "joern")
    found = shutil.which("joern")
    if found:
        return found
    for candidate in (
        Path.home() / ".local/share/joern/joern-cli/joern",
        Path("/opt/joern/joern-cli/joern"),
    ):
        if candidate.exists():
            return str(candidate)
    return None


def joern_parse_cmd(joern_bin: str) -> str:
    """joern-parse ships alongside `joern` in the same joern-cli directory."""
    return str(Path(joern_bin).parent / "joern-parse")


def write_stub(out_path: Path, reason: str, repo_path: Path, extra: dict = None):
    stub = {
        "available": False, "reason": reason, "repo_path": str(repo_path),
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }
    if extra:
        stub.update(extra)
    out_path.write_text(json.dumps(stub, indent=2), encoding="utf-8")


def run_language(joern_bin: str, repo_path: Path, lang: str, workdir: Path):
    """Build the CPG for one language and extract taint paths. Returns
    (paths_json_dict, error_message)."""
    cpg_bin = workdir / f"joern-cpg-{lang}.bin"
    # --exclude-regex is documented upstream but not supported by every
    # joern-parse build — confirmed absent from `joern-parse --help` on the
    # version actually installed here (real check, not assumed from docs).
    # Joern's per-language frontends (js2cpg/pysrc2cpg/javasrc2cpg) already
    # default-exclude node_modules/build/dist, so omitting it costs nothing
    # on this build; --list-languages / --help confirmed no equivalent flag.
    parse_proc = subprocess.run(
        [joern_parse_cmd(joern_bin), str(repo_path),
         "--language", LANG_FLAGS[lang],
         "--output", str(cpg_bin)],
        capture_output=True, text=True, timeout=1800,
    )
    if parse_proc.returncode != 0 or not cpg_bin.exists():
        return None, (parse_proc.stderr or "joern-parse failed")[:500]

    out_file = workdir / f"cpg-paths-{lang}.json"
    # `--param key=value`, repeated per key — confirmed via `joern --help` on
    # the actual installed build. The single-flag `--params "k=v,k2=v2"` form
    # (assumed from upstream docs in an earlier draft) doesn't exist on this
    # version and fails with "Unknown option --params".
    script_proc = subprocess.run(
        [joern_bin, "--script", str(SCRIPT_DIR / "joern_extract.sc"),
         "--param", f"cpgFile={cpg_bin}",
         "--param", f"outFile={out_file}"],
        capture_output=True, text=True, timeout=1800,
    )
    if not out_file.exists():
        return None, (script_proc.stderr or "joern script produced no output")[:500]

    try:
        data = json.loads(out_file.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        return None, f"invalid cpg output json: {e}"
    return data, None


def merge_language_outputs(per_lang: dict) -> dict:
    taint_paths, call_graph, unreachable, sinks_found = [], [], [], []
    seen_taint, seen_edges, seen_sinks = set(), set(), set()
    coverage = {"methods_analyzed": 0, "calls_analyzed": 0, "sinks_found": 0,
                "taint_paths_found": 0, "unreachable_sinks": 0}
    degraded = False
    degraded_reasons = []

    for lang, data in per_lang.items():
        for tp in data.get("taint_paths", []):
            key = (tp.get("source_file"), tp.get("source_line"), tp.get("sink_file"), tp.get("sink_line"))
            if key not in seen_taint:
                seen_taint.add(key)
                taint_paths.append(tp)
        for edge in data.get("call_graph", []):
            key = (edge.get("caller_file"), edge.get("caller_method"), edge.get("callee_file"), edge.get("callee_method"))
            if key not in seen_edges:
                seen_edges.add(key)
                call_graph.append(edge)
        for sink in data.get("sinks_found", []):
            key = (sink.get("file"), sink.get("line"), sink.get("sink_name"))
            if key not in seen_sinks:
                seen_sinks.add(key)
                sinks_found.append(sink)
        unreachable.extend(data.get("unreachable_sinks", []))
        for k in coverage:
            coverage[k] += data.get("coverage", {}).get(k, 0)
        if data.get("degraded"):
            degraded = True
            reason = data.get("degraded_reason")
            if reason and reason not in degraded_reasons:
                degraded_reasons.append(reason)

    result = {
        "taint_paths": taint_paths,
        "sinks_found": sinks_found,
        "call_graph": call_graph[:2000],
        "unreachable_sinks": unreachable,
        "coverage": coverage,
    }
    if degraded:
        result["degraded"] = True
        result["degraded_reason"] = " | ".join(degraded_reasons)
    return result


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("repo_path")
    ap.add_argument("--manifest", default="./language-manifest.json")
    ap.add_argument("--cpg-out", default="./cpg-output.json")
    ap.add_argument("--joern-bin", default=None)
    ap.add_argument("--workdir", default=None)
    args = ap.parse_args()

    repo_path = Path(args.repo_path).resolve()
    out_path = Path(args.cpg_out)
    workdir = Path(args.workdir) if args.workdir else out_path.parent

    joern_bin = find_joern_bin(args.joern_bin)
    if not joern_bin:
        write_stub(out_path, "joern_not_installed", repo_path)
        print("joern-parse: Joern not installed — CPG analysis skipped.")
        return 0

    manifest_path = Path(args.manifest)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8-sig")) if manifest_path.exists() else {}
    languages = [l.lower() for l in manifest.get("languages", [])] or (
        [manifest["primary_language"].lower()] if manifest.get("primary_language") else []
    )

    supported = [l for l in languages if l in LANG_FLAGS]
    unsupported = [l for l in languages if l in UNSUPPORTED]
    if not supported:
        reason = "language_not_supported" if unsupported else "no_languages_in_manifest"
        write_stub(out_path, reason, repo_path)
        print(f"joern-parse: no supported language for Joern ({languages}) — CPG analysis skipped.")
        return 0

    # dedupe javascript/typescript -> one joern run under a shared flag
    seen_flags = set()
    run_langs = []
    for lang in supported:
        flag = LANG_FLAGS[lang]
        if flag not in seen_flags:
            seen_flags.add(flag)
            run_langs.append(lang)

    version_proc = subprocess.run([joern_bin, "--version"], capture_output=True, text=True)
    tool_version = version_proc.stdout.strip()

    per_lang_data = {}
    errors = []
    for lang in run_langs:
        data, err = run_language(joern_bin, repo_path, lang, workdir)
        if err:
            errors.append(f"{lang}: {err}")
            continue
        per_lang_data[lang] = data

    if not per_lang_data:
        write_stub(out_path, "parse_failed", repo_path, {"error": "; ".join(errors)[:1000]})
        print(f"joern-parse: all languages failed — {errors}")
        return 0

    merged = merge_language_outputs(per_lang_data)

    output = {
        "available": True,
        "tool": "joern",
        "tool_version": tool_version,
        "repo_path": str(repo_path),
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "languages_analyzed": list(per_lang_data.keys()),
        **merged,
    }
    out_path.write_text(json.dumps(output, indent=2), encoding="utf-8")

    # taint_paths is empty in degraded mode (see joern_extract.sc header) —
    # sinks_found is the populated signal to summarize instead.
    sink_type_counts = {}
    for s in merged.get("sinks_found", []):
        t = s.get("sink_type", "unknown")
        sink_type_counts[t] = sink_type_counts.get(t, 0) + 1

    print("joern-parse complete.")
    print(f"  Repo              : {repo_path}")
    print(f"  Languages parsed  : {', '.join(per_lang_data.keys())}")
    if merged.get("degraded"):
        print(f"  Mode              : DEGRADED — {merged.get('degraded_reason')}")
    print(f"  Sinks found       : {len(merged.get('sinks_found', []))}")
    print(f"  Taint paths found : {len(merged['taint_paths'])}")
    print(f"  Call graph edges  : {len(merged['call_graph'])}")
    print(f"  Unreachable sinks : {len(merged['unreachable_sinks'])}")
    print("  Top sink types:")
    for t, c in sorted(sink_type_counts.items(), key=lambda x: -x[1]):
        print(f"    {t:18}: {c}")
    print(f"  Output            : {out_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
