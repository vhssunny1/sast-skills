#!/usr/bin/env python3
"""
Headless CLI entrypoint for the SAST pipeline orchestrator — same run_pipeline()
as the web harness (auto-resume, batching, raw-output logging, dedup), but prints
progress straight to the terminal instead of streaming over SSE. No server, no login.

Usage:
    python cli.py <repo-path-or-git-url> [options]

Options:
    --ground-truth <path>   ground truth file for precision/recall
    --skip-taint            skip taint-trace step
    --skip-config-audit     skip config-audit step
    --skip-tree-sitter      skip tree-sitter AST crawl (use heuristic crawl only)
    --skip-joern            skip Joern CPG generation
    --codeql                run codeql-scan alongside find-vulns
    --dast                  generate DAST test script at the end
    --fresh                 ignore any incomplete prior run, start clean
    --resume <run_id>       resume a specific run_id instead of auto-detecting

Exit code is 0 on pipeline success, 1 on failure.
"""

import argparse
import asyncio
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

import config
from pipeline import run_pipeline


def _resolve_repo(source: str) -> Path:
    """
    Accept either a local folder path or a GitHub/git URL.
    - Local path: must exist as a directory, used directly.
    - URL (http/https/git@): cloned into REPOS_DIR (pulled if already cloned).
    Duplicated from harness.py rather than imported, so the CLI has no
    dependency on FastAPI/uvicorn/auth — only what pipeline.py itself needs.
    KEEP IN SYNC with harness.py's _resolve_repo — these drifted apart once
    already (different clone depth, pull flags, and this one had no timeout
    at all, risking an indefinite hang on a stalled clone/pull).
    """
    local = Path(source)
    if local.exists() and local.is_dir():
        return local.resolve()

    if not (source.startswith("http://") or source.startswith("https://")
            or source.startswith("git@") or source.startswith("git://")):
        raise RuntimeError(
            f"Not a valid local path or git URL: {source!r}\n"
            "Provide a local folder path (e.g. /root/sast-tools/juice-shop) "
            "or a full GitHub URL (e.g. https://github.com/org/repo.git)"
        )

    config.REPOS_DIR.mkdir(parents=True, exist_ok=True)
    repo_name = source.rstrip("/").split("/")[-1]
    if repo_name.endswith(".git"):
        repo_name = repo_name[:-4]
    repo_path = config.REPOS_DIR / repo_name

    if repo_path.exists():
        result = subprocess.run(["git", "-C", str(repo_path), "pull", "--ff-only"],
                                 capture_output=True, text=True, timeout=120)
    else:
        result = subprocess.run(
            ["git", "clone", "--depth", "1", source, str(repo_path)],
            capture_output=True, text=True, timeout=300,
        )
    if result.returncode != 0:
        raise RuntimeError(f"git clone/pull failed: {result.stderr[:500]}")
    return repo_path.resolve()


def _fmt_duration(seconds):
    if seconds is None:
        return "?"
    m, s = divmod(int(seconds), 60)
    return f"{m}m{s:02d}s" if m else f"{s}s"


def make_console_emit():
    """Prints each pipeline event as a single readable line to stdout."""

    def emit_line(text: str):
        print(text, flush=True)

    async def emit(event: dict):
        etype = event.get("type")

        if etype == "pipeline_start":
            tag = "RESUMING" if event.get("resuming") else "STARTING"
            emit_line(f"\n[{tag}] run {event['run_id']}")
        elif etype == "resume":
            emit_line(f"[RESUME] continuing after failed step: {event.get('failed_at')}")
        elif etype == "group_start":
            skills = ", ".join(event.get("skills", []))
            emit_line(f"\n=== Group {event.get('group')}: {skills} ===")
        elif etype == "step_start":
            emit_line(f"  -> {event['step']} ...")
        elif etype == "step_complete":
            dur = _fmt_duration(event.get("duration_seconds"))
            delta = event.get("findings_delta")
            delta_str = f", findings {'+' if (delta or 0) >= 0 else ''}{delta}" if delta is not None else ""
            cost = event.get("cost_usd")
            cost_str = f", ${cost:.4f}" if cost else ""
            emit_line(f"  OK {event['step']} ({dur}{delta_str}{cost_str})")
        elif etype == "step_skipped":
            emit_line(f"  -- {event['step']} skipped ({event.get('reason')})")
        elif etype == "step_error":
            dur = _fmt_duration(event.get("duration_seconds"))
            emit_line(f"  FAIL {event['step']} ({dur}): {event.get('error')}")
        elif etype == "warning":
            emit_line(f"  [warning] {event.get('message')}")
        elif etype == "skill_start":
            pass  # too granular for the top-level CLI view; step_start covers it
        elif etype == "skill_complete":
            pass
        elif etype == "fatal_error":
            emit_line(f"\n[FATAL] {event.get('error')}")
        elif etype == "error":
            emit_line(f"\n[ERROR] {event.get('message')}")
        elif etype == "pipeline_complete":
            dur = _fmt_duration(event.get("total_duration_seconds"))
            totals = event.get("token_usage_totals") or {}
            cost = totals.get("cost_usd")
            tok_in = totals.get("input_tokens", 0) + totals.get("cache_creation_input_tokens", 0) \
                + totals.get("cache_read_input_tokens", 0)
            tok_out = totals.get("output_tokens", 0)
            cost_str = f", ${cost:.4f} ({tok_in:,} in / {tok_out:,} out tokens)" if cost else ""
            emit_line(f"\n[DONE] run {event['run_id']}: {event.get('total_findings')} findings "
                      f"in {dur}{cost_str}")
        else:
            emit_line(f"  {event}")

    return emit


async def main_async(args) -> int:
    run_id = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    emit = make_console_emit()

    try:
        repo_path = await asyncio.get_event_loop().run_in_executor(
            None, _resolve_repo, args.repo
        )
    except Exception as exc:
        print(f"[ERROR] could not resolve repo path/URL: {exc}", file=sys.stderr)
        return 1

    print(f"Repo resolved to: {repo_path}")

    try:
        await run_pipeline(
            run_id=run_id,
            repo_path=repo_path,
            git_url=args.repo,
            emit=emit,
            ground_truth=args.ground_truth,
            skip_taint=args.skip_taint,
            skip_config_audit=args.skip_config_audit,
            skip_tree_sitter=args.skip_tree_sitter,
            skip_joern=args.skip_joern,
            codeql=args.codeql,
            dast=args.dast,
            fresh=args.fresh,
            resume_run_id=args.resume,
            recheck_tier5=args.recheck_tier5,
        )
    except Exception as exc:
        print(f"\n[FATAL] pipeline raised: {exc}", file=sys.stderr)
        return 1

    run_dir = config.RUNS_DIR / run_id
    # If this run resumed a prior run_dir instead of using its own fresh run_id,
    # run_pipeline's internal log still reports the real directory name via the
    # printed "[RESUME] run <id>" line above — nothing further to resolve here.
    print(f"\nDone. Artifacts under: {config.RUNS_DIR}")
    return 0


def main():
    parser = argparse.ArgumentParser(description="Headless CLI for the SAST pipeline")
    parser.add_argument("repo", help="Local repo path or git URL to scan")
    parser.add_argument("--ground-truth", default=None)
    parser.add_argument("--skip-taint", action="store_true")
    parser.add_argument("--skip-config-audit", action="store_true")
    parser.add_argument("--skip-tree-sitter", action="store_true")
    parser.add_argument("--skip-joern", action="store_true")
    parser.add_argument("--codeql", action="store_true")
    parser.add_argument("--dast", action="store_true")
    parser.add_argument("--fresh", action="store_true")
    parser.add_argument("--resume", default=None, metavar="RUN_ID")
    parser.add_argument("--recheck-tier5", action="store_true",
                         help="After the normal find-vulns pass, re-scan only security_priority:5 "
                              "files a second time (fresh LLM read) to recover run-to-run misses. "
                              "Real Juice Shop test: $1.11 extra recovered all baseline findings "
                              "plus 2 new ones, vs ~$6-12 for a full 2-3x re-run.")
    args = parser.parse_args()

    exit_code = asyncio.run(main_async(args))
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
