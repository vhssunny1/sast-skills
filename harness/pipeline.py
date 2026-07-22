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
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Awaitable, Optional

import config
from agent import run_skill

# Maps failed_at_step → the last good findings snapshot to restore
RESUME_ARTIFACT_MAP = {
    "scan-report":           "findings-validated.json",
    "generate-dast-tests":   "findings-validated.json",
    "validate-findings":     "findings-traced.json",
    "taint-trace":           "findings-cross-lang.json",   # fallback: findings-raw.json
    "cross-language-taint":  "findings-raw.json",
    "find-vulns":            "findings-after-config-audit.json",
    "config-audit":          None,
    "crawl":                 None,
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

    for fname in ("crawl-output.json", "language-manifest.json"):
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
                  findings_after: Optional[int], artifacts: list, notes: dict):
    for s in log["steps"]:
        if s.get("step") == step_name and s.get("status") == "started":
            s.update({
                "status": "completed",
                "completed_at": now_iso(),
                "findings_after": findings_after,
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


def _log_fail(log: dict, log_path: Path, step_name: str, error: str):
    for s in log["steps"]:
        if s.get("step") == step_name and s.get("status") == "started":
            s.update({"status": "failed", "completed_at": now_iso(), "error": error})
            break
    log["status"] = "failed"
    log["failed_at_step"] = step_name
    _write_log(log_path, log)


def _count_findings(workdir: Path) -> Optional[int]:
    f = workdir / "findings.json"
    if not f.exists():
        return None
    try:
        return json.loads(f.read_text()).get("total_findings", 0)
    except Exception:
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

        findings_before = _count_findings(workdir)
        _log_start(log, log_path, skill_name, findings_before)
        await emit({"type": "step_start", "step": skill_name})

        try:
            await run_skill(skill_name, repo_path, workdir, extra_context, emit)
        except Exception as exc:
            _log_fail(log, log_path, skill_name, str(exc))
            await emit({"type": "step_error", "step": skill_name, "error": str(exc)})
            return False

        findings_after = _count_findings(workdir)
        arts = artifacts or []
        notes = notes_fn() if notes_fn else {}
        _log_complete(log, log_path, skill_name, findings_after, arts, notes)
        await emit({"type": "step_complete", "step": skill_name,
                    "findings_after": findings_after})
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

    # ── Group 1: crawl + config-audit concurrently ────────────────────────────
    await emit({"type": "group_start", "group": 1,
                "skills": crawl_skills + ([] if skip_config_audit else ["config-audit"])})

    group1_tasks = []
    for skill in crawl_skills:
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

    # ── Group 2: find-vulns concurrently ──────────────────────────────────────
    await emit({"type": "group_start", "group": 2, "skills": findvulns_skills})

    group2_tasks = [
        step(skill, extra_context="Arguments: --crawl crawl-output.json",
             artifacts=[f"findings-{skill.replace('find-vulns-','')}.json"])
        for skill in findvulns_skills
    ]
    results = await asyncio.gather(*group2_tasks)
    if not all(results):
        return

    # merge findings if polyglot
    if polyglot and len(findvulns_skills) > 1:
        prefix_map = {"find-vulns-python": "PY", "find-vulns-typescript": "TS",
                      "find-vulns-java": "JAVA"}
        all_findings = []
        counters = {}
        existing = workdir / "findings.json"
        if existing.exists():
            base = json.loads(existing.read_text())
            all_findings.extend([f for f in base.get("findings", [])
                                  if f.get("id", "").startswith("CONFIG")])
        for skill in findvulns_skills:
            lang = skill.replace("find-vulns-", "")
            src = workdir / f"findings-{lang}.json"
            if src.exists():
                data = json.loads(src.read_text())
                prefix = prefix_map.get(skill, lang.upper())
                counters[prefix] = counters.get(prefix, 0)
                for f in data.get("findings", []):
                    counters[prefix] += 1
                    f["id"] = f"{prefix}-{counters[prefix]:03d}"
                    all_findings.append(f)

        merged_findings = {
            "scanned_at": now_iso(), "repo_path": str(repo_path),
            "language": "polyglot", "total_findings": len(all_findings),
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

    total = _count_findings(workdir) or 0
    await emit({"type": "pipeline_complete", "run_id": run_dir.name,
                "total_findings": total, "run_dir": str(run_dir)})


def _count_by_severity(findings: list) -> dict:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in findings:
        sev = f.get("severity", "").lower()
        if sev in counts:
            counts[sev] += 1
    return counts
