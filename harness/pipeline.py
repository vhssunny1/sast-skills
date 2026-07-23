"""
Pipeline orchestrator — replaces sast-full-scan.md.
Runs skills in three execution groups:
  Group 1 (concurrent): crawl-* + config-audit
  Group 2 (concurrent): find-vulns-*
  Group 3 (sequential): cross-language-taint → taint-trace → validate → scan-report
Includes auto-resume: detects the most recent incomplete run for the same repo.
"""

import asyncio
import json
import os
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Awaitable, Optional

import config
from agent import run_skill

# Ensure Joern and Java are findable regardless of how the harness was launched.
# These are the known install locations on this machine.
_EXTRA_PATH_DIRS = [
    r"C:\Users\Harikrishna_Valugond\Downloads\joern-cli\joern-cli",
    r"C:\Program Files\Microsoft\jdk-21.0.11.10-hotspot\bin",
    r"C:\Program Files\LLVM\bin",
]
_current_path = os.environ.get("PATH", "")
for _d in _EXTRA_PATH_DIRS:
    if _d not in _current_path:
        os.environ["PATH"] = _current_path + os.pathsep + _d
        _current_path = os.environ["PATH"]

# Maps failed_at_step → the last good findings snapshot to restore
RESUME_ARTIFACT_MAP = {
    "scan-report":           "findings-validated.json",
    "generate-dast-tests":   "findings-validated.json",
    "validate-findings":     "findings-traced.json",
    "taint-trace":           "findings-cross-lang.json",   # fallback: findings-raw.json
    "cross-language-taint":  "findings-raw.json",
    "find-vulns":            "findings-after-config-audit.json",
    "codeql-scan":           "findings-after-config-audit.json",
    "config-audit":          None,
    "crawl":                 None,
    "joern-parse":           None,
    "tree-sitter-crawl":     None,
    "detect-language":       None,
}


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# ── Auto-resume detection ──────────────────────────────────────────────────────

def find_incomplete_run(repo_path: str, resume_run_id: Optional[str] = None) -> Optional[dict]:
    """Scan sast-runs/ for the most recent failed/in_progress run for this repo."""
    if not config.RUNS_DIR.exists():
        return None
    candidates = []
    for run_dir in config.RUNS_DIR.iterdir():
        if not run_dir.is_dir():
            continue
        if resume_run_id and run_dir.name != resume_run_id:
            continue
        log_file = run_dir / "run-log.json"
        if not log_file.exists():
            continue
        try:
            log = json.loads(log_file.read_text())
        except Exception:
            continue
        if log.get("repo_path") != repo_path:
            continue
        if log.get("status") not in ("failed", "in_progress"):
            continue
        candidates.append((log.get("started_at", ""), run_dir, log))

    if not candidates:
        return None
    candidates.sort(key=lambda x: x[0], reverse=True)
    _, run_dir, log = candidates[0]
    return {"run_dir": run_dir, "log": log}


def restore_artifacts(run_dir: Path, failed_at_step: str, workdir: Path):
    """Copy last good artifacts from prior run into the current workdir."""
    artifact_name = RESUME_ARTIFACT_MAP.get(failed_at_step)
    if artifact_name:
        src = run_dir / artifact_name
        if not src.exists():
            # one level of fallback
            if artifact_name == "findings-cross-lang.json":
                src = run_dir / "findings-raw.json"
            elif artifact_name == "findings-after-config-audit.json":
                src = None
        if src and src.exists():
            shutil.copy(src, workdir / "findings.json")

    for fname in ("crawl-output.json", "language-manifest.json", "cpg-output.json"):
        src = run_dir / fname
        if src.exists():
            shutil.copy(src, workdir / fname)


# ── Run-log helpers ────────────────────────────────────────────────────────────

def _write_log(log_path: Path, log: dict):
    log_path.write_text(json.dumps(log, indent=2), encoding="utf-8")


def _step_entry(log: dict, step_name: str) -> Optional[dict]:
    for s in log.get("steps", []):
        if s.get("step") == step_name:
            return s
    return None


def _already_completed(log: dict, step_name: str) -> bool:
    e = _step_entry(log, step_name)
    return e is not None and e.get("status") == "completed"


def _log_start(log: dict, log_path: Path, step_name: str, findings_before: Optional[int]):
    log["steps"].append({
        "step": step_name,
        "status": "started",
        "started_at": now_iso(),
        "findings_before": findings_before,
    })
    _write_log(log_path, log)


def _log_complete(log: dict, log_path: Path, step_name: str,
                  findings_after: Optional[int], artifacts: list, notes: dict,
                  duration_seconds: Optional[float] = None):
    for s in log["steps"]:
        if s.get("step") == step_name and s.get("status") == "started":
            findings_before = s.get("findings_before")
            findings_delta = (findings_after - findings_before
                              if findings_after is not None and findings_before is not None else None)
            s.update({
                "status": "completed",
                "completed_at": now_iso(),
                "duration_seconds": duration_seconds,
                "findings_after": findings_after,
                "findings_delta": findings_delta,
                "output_artifacts": artifacts,
                "error": None,
                "notes": notes,
            })
            break
    _write_log(log_path, log)


def _log_skip(log: dict, log_path: Path, step_name: str, reason: str):
    log["steps"].append({
        "step": step_name, "status": "skipped", "skip_reason": reason,
        "started_at": None, "completed_at": None, "duration_seconds": None,
        "findings_before": None, "findings_after": None,
        "output_artifacts": [], "error": None, "notes": {},
    })
    _write_log(log_path, log)


def _log_fail(log: dict, log_path: Path, step_name: str, error: str,
              duration_seconds: Optional[float] = None):
    for s in log["steps"]:
        if s.get("step") == step_name and s.get("status") == "started":
            s.update({"status": "failed", "completed_at": now_iso(), "error": error,
                      "duration_seconds": duration_seconds})
            break
    log["status"] = "failed"
    log["failed_at_step"] = step_name
    _write_log(log_path, log)


async def _count_findings(workdir: Path) -> Optional[int]:
    f = workdir / "findings.json"
    # Windows can briefly hold the file handle/lock open for a moment after the
    # `claude` subprocess exits (AV scan, delayed handle release), so retry
    # a couple of times before giving up rather than silently reporting null.
    for attempt in range(3):
        if not f.exists():
            if attempt < 2:
                await asyncio.sleep(0.3)
                continue
            return None
        try:
            return json.loads(f.read_text()).get("total_findings", 0)
        except Exception:
            if attempt < 2:
                await asyncio.sleep(0.3)
                continue
            return None
    return None


# ── Main pipeline ──────────────────────────────────────────────────────────────

async def run_pipeline(
    run_id: str,
    repo_path: Path,
    git_url: str,
    emit: Callable[[dict], Awaitable[None]],
    ground_truth: Optional[str] = None,
    skip_taint: bool = False,
    skip_config_audit: bool = False,
    skip_tree_sitter: bool = False,
    skip_joern: bool = False,
    codeql: bool = False,
    dast: bool = False,
    fresh: bool = False,
    resume_run_id: Optional[str] = None,
):
    run_dir = config.RUNS_DIR / run_id
    workdir = run_dir / "workdir"
    log_path = run_dir / "run-log.json"

    # ── Step 0: auto-resume detection ─────────────────────────────────────────
    resuming = False
    prior = None
    if not fresh:
        prior = find_incomplete_run(str(repo_path), resume_run_id)

    if prior:
        resuming = True
        run_dir = prior["run_dir"]
        workdir = run_dir / "workdir"
        log_path = run_dir / "run-log.json"
        log = prior["log"]
        failed_at = log.get("failed_at_step")
        log["status"] = "in_progress"
        log["resumed_at"] = now_iso()
        _write_log(log_path, log)
        restore_artifacts(run_dir, failed_at, workdir)
        await emit({"type": "resume", "run_id": run_dir.name, "failed_at": failed_at})
    else:
        run_dir.mkdir(parents=True, exist_ok=True)
        workdir.mkdir(parents=True, exist_ok=True)
        log = {
            "run_id": run_id,
            "repo_path": str(repo_path),
            "git_url": git_url,
            "started_at": now_iso(),
            "status": "in_progress",
            "failed_at_step": None,
            "steps": [],
        }
        _write_log(log_path, log)

    await emit({"type": "pipeline_start", "run_id": run_dir.name, "resuming": resuming})

    async def step(skill_name: str, extra_context: str = "", skip_reason: str = None,
                   artifacts: list = None, notes_fn=None):
        """Run one skill, handling resume-skip and error capture."""
        if resuming and _already_completed(log, skill_name):
            _log_skip(log, log_path, skill_name, "already completed in prior run")
            await emit({"type": "step_skipped", "step": skill_name, "reason": "resumed"})
            return True

        if skip_reason:
            _log_skip(log, log_path, skill_name, skip_reason)
            await emit({"type": "step_skipped", "step": skill_name, "reason": skip_reason})
            return True

        findings_before = await _count_findings(workdir)
        _log_start(log, log_path, skill_name, findings_before)
        await emit({"type": "step_start", "step": skill_name})
        t0 = asyncio.get_event_loop().time()

        try:
            await run_skill(skill_name, repo_path, workdir, extra_context, emit)
        except Exception as exc:
            duration = round(asyncio.get_event_loop().time() - t0, 1)
            _log_fail(log, log_path, skill_name, str(exc), duration)
            await emit({"type": "step_error", "step": skill_name, "error": str(exc),
                        "duration_seconds": duration})
            return False

        duration = round(asyncio.get_event_loop().time() - t0, 1)
        findings_after = await _count_findings(workdir)
        findings_delta = (findings_after - findings_before
                          if findings_after is not None and findings_before is not None else None)
        arts = artifacts or []
        notes = notes_fn() if notes_fn else {}
        _log_complete(log, log_path, skill_name, findings_after, arts, notes, duration)
        await emit({"type": "step_complete", "step": skill_name,
                    "findings_after": findings_after, "findings_delta": findings_delta,
                    "duration_seconds": duration})
        return True

    # ── Step 1: detect-language ────────────────────────────────────────────────
    ok = await step("detect-language",
                    extra_context=f"Arguments: {repo_path}",
                    artifacts=["language-manifest.json"])
    if not ok:
        return

    lang_manifest_path = workdir / "language-manifest.json"
    if not lang_manifest_path.exists():
        await emit({"type": "error", "message": "language-manifest.json not produced"})
        return
    lang_manifest = json.loads(lang_manifest_path.read_text())
    crawl_skills    = lang_manifest.get("pipeline", {}).get("crawl", [])
    findvulns_skills = lang_manifest.get("pipeline", {}).get("find_vulns", [])
    polyglot        = lang_manifest.get("polyglot", False)
    shutil.copy(workdir / "language-manifest.json", run_dir / "language-manifest.json")

    # ── Step 2a: tree-sitter-crawl ────────────────────────────────────────────
    tree_sitter_ran = False
    if skip_tree_sitter:
        _log_skip(log, log_path, "tree-sitter-crawl", "--skip-tree-sitter")
        await emit({"type": "step_skipped", "step": "tree-sitter-crawl",
                    "reason": "--skip-tree-sitter"})
    elif not shutil.which("tree-sitter"):
        _log_skip(log, log_path, "tree-sitter-crawl", "tree-sitter CLI not installed")
        await emit({"type": "step_skipped", "step": "tree-sitter-crawl",
                    "reason": "tree-sitter CLI not installed"})
    else:
        ok = await step(
            "crawl-tree-sitter",
            extra_context=f"Arguments: {repo_path} --manifest language-manifest.json",
            artifacts=["crawl-output-treesitter.json"],
        )
        if ok:
            ts_out = workdir / "crawl-output.json"
            if ts_out.exists():
                try:
                    data = json.loads(ts_out.read_text())
                    if data.get("ts_available", False):
                        tree_sitter_ran = True
                        shutil.copy(ts_out, run_dir / "crawl-output-treesitter.json")
                except Exception:
                    pass  # parse error — fall through to heuristic crawl

    # ── Step 2b: joern-parse ──────────────────────────────────────────────────
    if skip_joern:
        _log_skip(log, log_path, "joern-parse", "--skip-joern")
        await emit({"type": "step_skipped", "step": "joern-parse", "reason": "--skip-joern"})
    elif not shutil.which("joern"):
        _log_skip(log, log_path, "joern-parse", "Joern not installed")
        await emit({"type": "step_skipped", "step": "joern-parse",
                    "reason": "Joern not installed"})
    else:
        # Pass the resolved absolute path explicitly — the LLM's own Bash tool
        # sandbox does not reliably inherit our os.environ PATH injection, so
        # PATH-based auto-detection inside the skill silently reports
        # "not installed" even though shutil.which() finds it here.
        joern_bin = shutil.which("joern")
        ok = await step(
            "joern-parse",
            extra_context=(f"Arguments: {repo_path} --manifest language-manifest.json "
                           f"--cpg-out cpg-output.json --joern-bin {joern_bin}"),
            artifacts=["cpg-output.json"],
        )
        if ok and (workdir / "cpg-output.json").exists():
            shutil.copy(workdir / "cpg-output.json", run_dir / "cpg-output.json")

    # ── Group 1: crawl + config-audit concurrently ────────────────────────────
    await emit({"type": "group_start", "group": 1,
                "skills": crawl_skills + ([] if skip_config_audit else ["config-audit"])})

    group1_tasks = []
    for skill in crawl_skills:
        if tree_sitter_ran:
            group1_tasks.append(step(skill,
                                     skip_reason="superseded by tree-sitter-crawl"))
        else:
            group1_tasks.append(step(skill, extra_context=f"Arguments: {repo_path}",
                                     artifacts=[f"crawl-output-{skill.replace('crawl-','')}.json"]))
    if not skip_config_audit:
        group1_tasks.append(step("config-audit", extra_context=f"Arguments: {repo_path}",
                                 artifacts=["findings-after-config-audit.json"]))
    else:
        group1_tasks.append(step("config-audit", skip_reason="--skip-config-audit"))

    results = await asyncio.gather(*group1_tasks)
    if not all(results):
        return

    # merge crawl outputs if polyglot
    if polyglot and len(crawl_skills) > 1:
        merged = {"language": "polyglot", "languages_detected": [], "files": [],
                  "entry_points": [], "frameworks": {}, "dependencies": []}
        dep_names = set()
        for skill in crawl_skills:
            lang = skill.replace("crawl-", "")
            src = workdir / f"crawl-output-{lang}.json"
            if src.exists():
                data = json.loads(src.read_text())
                merged["files"].extend(data.get("files", []))
                merged["entry_points"].extend(data.get("entry_points", []))
                merged["frameworks"].update(data.get("frameworks", {}) if isinstance(data.get("frameworks"), dict) else {lang: data.get("framework", "unknown")})
                merged["languages_detected"].append(data.get("language", lang))
                for dep in data.get("dependencies", []):
                    if dep.get("name") not in dep_names:
                        dep_names.add(dep.get("name"))
                        merged["dependencies"].append(dep)
        merged["total_files"] = len(merged["files"])
        (workdir / "crawl-output.json").write_text(json.dumps(merged, indent=2))

    shutil.copy(workdir / "crawl-output.json", run_dir / "crawl-output.json")
    if (workdir / "findings.json").exists():
        shutil.copy(workdir / "findings.json", run_dir / "findings-after-config-audit.json")

    await emit({"type": "group_complete", "group": 1})

    # ── Group 2: find-vulns (batched per language, sequential) + optional codeql ──
    # find-vulns-* skills all hardcode "overwrite findings.json" in their own
    # instructions (they don't accept an --output flag), so:
    #  1. Languages must run SEQUENTIALLY, not concurrently — concurrent runs would
    #     race on the same workdir/findings.json and silently clobber each other.
    #  2. Each language's own file list is split into fixed-size batches so a single
    #     agent turn is never asked to exhaustively read hundreds of files at once —
    #     that was silently truncating coverage (e.g. 27/232 required files read).
    #  3. CONFIG-* findings from config-audit are explicitly preserved across the
    #     merge — the skills' "overwrite" behavior was silently deleting them.
    cpg_arg = " --cpg cpg-output.json" if (workdir / "cpg-output.json").exists() else ""
    g2_skill_list = findvulns_skills + (["codeql-scan"] if codeql else [])
    await emit({"type": "group_start", "group": 2, "skills": g2_skill_list})

    try:
        crawl_data = json.loads((workdir / "crawl-output.json").read_text())
    except Exception:
        crawl_data = {}

    async def run_find_vulns_language(skill_name: str):
        lang = skill_name.replace("find-vulns-", "")
        prefix = FIND_VULNS_PREFIX.get(skill_name, lang.upper())
        priority_files = _priority_files_for_language(crawl_data, lang, polyglot)
        batches = _batch(priority_files, FIND_VULNS_BATCH_SIZE) or [[]]

        accumulated = []
        counter = 0
        for i, batch_files in enumerate(batches):
            multi = len(batches) > 1
            step_name = skill_name if not multi else f"{skill_name}-batch{i+1}of{len(batches)}"
            batch_note = ""
            if multi:
                file_list = "\n".join(f"- {p}" for p in batch_files)
                batch_note = (
                    f"\n\nBATCH MODE (enforced by harness for full coverage): this is batch "
                    f"{i+1} of {len(batches)}. Restrict Step 4 file analysis EXCLUSIVELY to "
                    f"these {len(batch_files)} pre-selected files this pass — do not read any "
                    f"other files, and do not skip any of these:\n{file_list}"
                )
            ok = await step(step_name,
                            extra_context=f"Arguments: --crawl crawl-output.json{cpg_arg}{batch_note}",
                            artifacts=[f"findings-{lang}-batch{i+1}.json"])
            if not ok:
                return False, prefix, accumulated
            out = workdir / "findings.json"
            if out.exists():
                try:
                    data = json.loads(out.read_text())
                    for f in data.get("findings", []):
                        counter += 1
                        f["id"] = f"{prefix}-{counter:03d}"
                        accumulated.append(f)
                except Exception:
                    pass
        return True, prefix, accumulated

    codeql_task = None
    if codeql:
        codeql_task = asyncio.create_task(step(
            "codeql-scan",
            extra_context=f"Arguments: {repo_path} --manifest language-manifest.json",
            artifacts=["codeql-output.json"],
        ))

    fv_results = []
    for skill in findvulns_skills:
        result = await run_find_vulns_language(skill)
        fv_results.append(result)
        if not result[0]:
            if codeql_task:
                await codeql_task
            return

    if codeql_task and not await codeql_task:
        return

    all_findings = []
    existing = workdir / "findings.json"
    if existing.exists():
        try:
            base = json.loads(existing.read_text())
            all_findings.extend([f for f in base.get("findings", [])
                                  if f.get("id", "").startswith("CONFIG")])
        except Exception:
            pass
    for _ok, _prefix, findings in fv_results:
        all_findings.extend(findings)

    merged_findings = {
        "scanned_at": now_iso(), "repo_path": str(repo_path),
        "language": "polyglot" if polyglot else (findvulns_skills[0].replace("find-vulns-", "")
                                                   if findvulns_skills else "unknown"),
        "total_findings": len(all_findings),
        "findings_by_severity": _count_by_severity(all_findings),
        "findings": all_findings,
    }
    (workdir / "findings.json").write_text(json.dumps(merged_findings, indent=2))

    shutil.copy(workdir / "findings.json", run_dir / "findings-raw.json")
    await emit({"type": "group_complete", "group": 2})

    # ── Group 3: sequential ───────────────────────────────────────────────────
    await emit({"type": "group_start", "group": 3,
                "skills": ["cross-language-taint", "taint-trace",
                           "validate-findings", "scan-report"]})

    if polyglot:
        ok = await step("cross-language-taint",
                        extra_context="Arguments: --findings findings.json --crawl crawl-output.json",
                        artifacts=["findings-cross-lang.json"])
        if ok and (workdir / "findings.json").exists():
            shutil.copy(workdir / "findings.json", run_dir / "findings-cross-lang.json")
        if not ok:
            return
    else:
        _log_skip(log, log_path, "cross-language-taint", "single-language repo")
        await emit({"type": "step_skipped", "step": "cross-language-taint",
                    "reason": "single-language repo"})

    if not skip_taint:
        ok = await step("taint-trace",
                        extra_context="Arguments: --findings findings.json --crawl crawl-output.json",
                        artifacts=["findings-traced.json"])
        if ok and (workdir / "findings.json").exists():
            shutil.copy(workdir / "findings.json", run_dir / "findings-traced.json")
        if not ok:
            return
    else:
        _log_skip(log, log_path, "taint-trace", "--skip-taint")
        await emit({"type": "step_skipped", "step": "taint-trace", "reason": "--skip-taint"})

    ok = await step("validate-findings",
                    extra_context="Arguments: --findings findings.json",
                    artifacts=["findings-validated.json"])
    if ok and (workdir / "findings.json").exists():
        shutil.copy(workdir / "findings.json", run_dir / "findings-validated.json")
    if not ok:
        return

    gt_arg = f"--ground-truth {ground_truth}" if ground_truth else ""
    ok = await step("scan-report",
                    extra_context=f"Arguments: --findings findings.json {gt_arg}",
                    artifacts=["scan-results.sarif", "scan-summary.md"])
    if not ok:
        return
    for fname in ("scan-results.sarif", "scan-summary.md"):
        src = workdir / fname
        if src.exists():
            shutil.copy(src, run_dir / fname)

    if dast:
        ok = await step("generate-dast-tests",
                        extra_context="Arguments: --findings findings.json",
                        artifacts=["dast-tests.py"])
        if ok and (workdir / "dast-tests.py").exists():
            shutil.copy(workdir / "dast-tests.py", run_dir / "dast-tests.py")
    else:
        _log_skip(log, log_path, "generate-dast-tests", "--dast not passed")

    # finalize
    shutil.copy(workdir / "findings.json", run_dir / "findings-final.json")
    log["status"] = "success"
    log["completed_at"] = now_iso()
    _write_log(log_path, log)

    total = await _count_findings(workdir) or 0
    started = datetime.fromisoformat(log["started_at"])
    completed = datetime.fromisoformat(log["completed_at"])
    total_duration = round((completed - started).total_seconds(), 1)
    await emit({"type": "pipeline_complete", "run_id": run_dir.name,
                "total_findings": total, "run_dir": str(run_dir),
                "total_duration_seconds": total_duration})


def _count_by_severity(findings: list) -> dict:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in findings:
        sev = f.get("severity", "").lower()
        if sev in counts:
            counts[sev] += 1
    return counts


FIND_VULNS_PREFIX = {"find-vulns-python": "PY", "find-vulns-typescript": "TS", "find-vulns-java": "JAVA"}
FIND_VULNS_BATCH_SIZE = 40


def _priority_files_for_language(crawl_data: dict, language: str, polyglot: bool) -> list:
    """Files with security_priority >= 2, highest priority first — the set find-vulns-*
    is contractually required to give a full read pass (CLAUDE.md coverage-completeness rule)."""
    files = crawl_data.get("files", [])
    if polyglot:
        files = [f for f in files if f.get("language") == language]
    prioritized = [f for f in files if f.get("security_priority", 0) >= 2]
    prioritized.sort(key=lambda f: f.get("security_priority", 0), reverse=True)
    return [f["path"] for f in prioritized if f.get("path")]


def _batch(items: list, size: int) -> list:
    return [items[i:i + size] for i in range(0, len(items), size)] if items else []
