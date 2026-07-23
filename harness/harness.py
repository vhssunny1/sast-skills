"""FastAPI harness — web UI + REST API for the SAST pipeline."""

import asyncio
import json
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

# uvicorn --reload switches the event loop to WindowsSelectorEventLoop on Windows,
# which cannot spawn subprocesses (NotImplementedError). Every skill invocation
# shells out to `claude`, so force ProactorEventLoop regardless of --reload.
if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())

from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.security import OAuth2PasswordRequestForm
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from sse_starlette.sse import EventSourceResponse

import config
import auth
from pipeline import run_pipeline

app = FastAPI(title="SAST Harness", version="1.0.0")
app.mount("/static", StaticFiles(directory=Path(__file__).parent / "static"), name="static")

# in-memory registry of active scan queues  {run_id: asyncio.Queue}
_active_queues: dict[str, asyncio.Queue] = {}
# in-memory registry of the background pipeline task per run {run_id: asyncio.Task}
_active_tasks: dict[str, asyncio.Task] = {}


# ── Auth ──────────────────────────────────────────────────────────────────────

@app.post("/api/auth/login")
async def login(form: OAuth2PasswordRequestForm = Depends()):
    if not auth.authenticate(form.username, form.password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="Incorrect username or password")
    token = auth.create_token(form.username)
    return {"access_token": token, "token_type": "bearer"}


# ── Scan management ───────────────────────────────────────────────────────────

class ScanRequest(BaseModel):
    git_url: str
    ground_truth: Optional[str] = None
    skip_taint: bool = False
    skip_config_audit: bool = False
    skip_tree_sitter: bool = False
    skip_joern: bool = False
    codeql: bool = False
    dast: bool = False
    fresh: bool = False
    resume_run_id: Optional[str] = None


def _resolve_repo(source: str) -> Path:
    """
    Accept either a local folder path or a GitHub/git URL.
    - Local path: must exist as a directory, used directly.
    - URL (http/https/git@): cloned into REPOS_DIR (pulled if already cloned).
    """
    # Detect local path: exists on disk, or starts with drive letter / UNC / Unix root
    local = Path(source)
    if local.exists() and local.is_dir():
        return local.resolve()

    # Treat as git URL
    if not (source.startswith("http://") or source.startswith("https://")
            or source.startswith("git@") or source.startswith("git://")):
        raise RuntimeError(
            f"Not a valid local path or git URL: {source!r}\n"
            "Provide a local folder path (e.g. C:/Users/.../juice-shop) "
            "or a full GitHub URL (e.g. https://github.com/org/repo.git)"
        )

    config.REPOS_DIR.mkdir(parents=True, exist_ok=True)
    repo_name = source.rstrip("/").split("/")[-1].removesuffix(".git")
    repo_path = config.REPOS_DIR / repo_name
    if repo_path.exists():
        subprocess.run(["git", "-C", str(repo_path), "pull", "--ff-only"],
                       capture_output=True, timeout=120)
    else:
        result = subprocess.run(
            ["git", "clone", "--depth", "1", source, str(repo_path)],
            capture_output=True, text=True, timeout=300,
        )
        if result.returncode != 0:
            raise RuntimeError(f"git clone failed: {result.stderr[:500]}")
    return repo_path


@app.post("/api/scans", dependencies=[Depends(auth.get_current_user)])
async def start_scan(req: ScanRequest):
    run_id = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    queue: asyncio.Queue = asyncio.Queue()
    _active_queues[run_id] = queue

    async def emit(event: dict):
        await queue.put(event)

    async def run():
        try:
            repo_path = await asyncio.get_event_loop().run_in_executor(
                None, _resolve_repo, req.git_url
            )
            await run_pipeline(
                run_id=run_id,
                repo_path=repo_path,
                git_url=req.git_url,
                emit=emit,
                ground_truth=req.ground_truth,
                skip_taint=req.skip_taint,
                skip_config_audit=req.skip_config_audit,
                skip_tree_sitter=req.skip_tree_sitter,
                skip_joern=req.skip_joern,
                codeql=req.codeql,
                dast=req.dast,
                fresh=req.fresh,
                resume_run_id=req.resume_run_id,
            )
        except asyncio.CancelledError:
            pass
        except Exception as exc:
            await emit({"type": "fatal_error", "error": str(exc)})
        finally:
            await queue.put(None)   # sentinel — stream is done
            _active_queues.pop(run_id, None)
            _active_tasks.pop(run_id, None)

    task = asyncio.create_task(run())
    _active_tasks[run_id] = task
    return {"run_id": run_id}


@app.get("/api/scans/{run_id}/stream")
async def stream_scan(run_id: str, token: str = ""):
    """SSE endpoint — streams pipeline events. Token via query param (EventSource can't set headers)."""
    # validate token manually — OAuth2PasswordBearer can't read query params
    try:
        auth.get_current_user(token)
    except Exception:
        async def denied():
            yield {"data": json.dumps({"type": "error", "error": "unauthorized"})}
        return EventSourceResponse(denied())

    queue = _active_queues.get(run_id)

    async def generator():
        if queue is None:
            yield {"data": json.dumps({"type": "error", "error": "run not found or already finished"})}
            return
        while True:
            event = await queue.get()
            if event is None:
                break
            yield {"data": json.dumps(event)}

    return EventSourceResponse(generator())


@app.get("/api/scans", dependencies=[Depends(auth.get_current_user)])
async def list_scans():
    """Return all run-log.json summaries sorted newest first."""
    if not config.RUNS_DIR.exists():
        return []
    runs = []
    for run_dir in sorted(config.RUNS_DIR.iterdir(), reverse=True):
        log_file = run_dir / "run-log.json"
        if not log_file.exists():
            continue
        try:
            log = json.loads(log_file.read_text())
            runs.append({
                "run_id":       log.get("run_id", run_dir.name),
                "repo_path":    log.get("repo_path", ""),
                "git_url":      log.get("git_url", ""),
                "started_at":   log.get("started_at", ""),
                "completed_at": log.get("completed_at"),
                "status":       log.get("status", "unknown"),
                "failed_at":    log.get("failed_at_step"),
                "active":       run_dir.name in _active_queues,
            })
        except Exception:
            continue
    return runs


@app.get("/api/scans/{run_id}", dependencies=[Depends(auth.get_current_user)])
async def get_scan(run_id: str):
    log_file = config.RUNS_DIR / run_id / "run-log.json"
    if not log_file.exists():
        raise HTTPException(404, "Run not found")
    return json.loads(log_file.read_text())


@app.get("/api/scans/{run_id}/files/{filename}")
async def download_file(run_id: str, filename: str, token: str = ""):
    """Download an output artifact from a completed run.

    Browsers navigating a plain <a href> link (new tab / direct download)
    can't attach an Authorization header, so accept the JWT via ?token= too,
    same as the SSE stream endpoint.
    """
    auth.get_current_user(token)
    allowed = {
        "scan-summary.md", "scan-results.sarif", "findings-final.json",
        "findings-raw.json", "findings-validated.json", "run-log.json",
        "dast-tests.py",
    }
    if filename not in allowed:
        raise HTTPException(400, "File not allowed")
    path = config.RUNS_DIR / run_id / filename
    if not path.exists():
        raise HTTPException(404, "File not found")
    return FileResponse(path, filename=filename)


async def _stop_run(run_id: str):
    """Cancel the background pipeline task (which kills its in-flight subprocess) and its SSE queue."""
    task = _active_tasks.pop(run_id, None)
    if task and not task.done():
        task.cancel()
        try:
            await task
        except (asyncio.CancelledError, Exception):
            pass
    if run_id in _active_queues:
        await _active_queues[run_id].put(None)
        _active_queues.pop(run_id, None)
        return True
    return False


@app.delete("/api/scans/{run_id}", dependencies=[Depends(auth.get_current_user)])
async def cancel_scan(run_id: str):
    """Stop a running scan: cancels its task (killing any in-flight `claude` subprocess)."""
    stopped = await _stop_run(run_id)
    return {"cancelled": stopped} if stopped else {"cancelled": False, "note": "scan not active"}


@app.delete("/api/scans/{run_id}/purge", dependencies=[Depends(auth.get_current_user)])
async def purge_scan(run_id: str):
    """Cancel if active, then permanently delete the run's artifacts from disk."""
    await _stop_run(run_id)
    run_dir = config.RUNS_DIR / run_id
    if not run_dir.exists():
        raise HTTPException(404, "Run not found")
    shutil.rmtree(run_dir, ignore_errors=True)
    return {"deleted": run_id}


@app.delete("/api/scans", dependencies=[Depends(auth.get_current_user)])
async def purge_all_scans():
    """Cancel every active scan and delete all run artifacts from disk."""
    for run_id in list(_active_tasks.keys()):
        await _stop_run(run_id)

    deleted = []
    if config.RUNS_DIR.exists():
        for run_dir in config.RUNS_DIR.iterdir():
            if run_dir.is_dir():
                shutil.rmtree(run_dir, ignore_errors=True)
                deleted.append(run_dir.name)
    return {"deleted": deleted, "count": len(deleted)}


# ── UI ────────────────────────────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
async def serve_ui():
    html = (Path(__file__).parent / "static" / "index.html").read_text(encoding="utf-8")
    return HTMLResponse(html)


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import uvicorn
    config.RUNS_DIR.mkdir(parents=True, exist_ok=True)
    config.REPOS_DIR.mkdir(parents=True, exist_ok=True)
    uvicorn.run("harness:app", host=config.HOST, port=config.PORT, reload=False)
