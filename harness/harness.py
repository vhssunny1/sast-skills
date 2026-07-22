"""FastAPI harness — web UI + REST API for the SAST pipeline."""

import asyncio
import json
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

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
    dast: bool = False
    fresh: bool = False
    resume_run_id: Optional[str] = None


def _clone_or_pull(git_url: str) -> Path:
    """Clone the repo if not present, pull if it is. Returns local path."""
    config.REPOS_DIR.mkdir(parents=True, exist_ok=True)
    repo_name = git_url.rstrip("/").split("/")[-1].removesuffix(".git")
    repo_path = config.REPOS_DIR / repo_name
    if repo_path.exists():
        subprocess.run(["git", "-C", str(repo_path), "pull", "--ff-only"],
                       capture_output=True, timeout=120)
    else:
        result = subprocess.run(
            ["git", "clone", "--depth", "1", git_url, str(repo_path)],
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
                None, _clone_or_pull, req.git_url
            )
            await run_pipeline(
                run_id=run_id,
                repo_path=repo_path,
                git_url=req.git_url,
                emit=emit,
                ground_truth=req.ground_truth,
                skip_taint=req.skip_taint,
                skip_config_audit=req.skip_config_audit,
                dast=req.dast,
                fresh=req.fresh,
                resume_run_id=req.resume_run_id,
            )
        except Exception as exc:
            await emit({"type": "fatal_error", "error": str(exc)})
        finally:
            await queue.put(None)   # sentinel — stream is done
            _active_queues.pop(run_id, None)

    asyncio.create_task(run())
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


@app.get("/api/scans/{run_id}/files/{filename}", dependencies=[Depends(auth.get_current_user)])
async def download_file(run_id: str, filename: str):
    """Download an output artifact from a completed run."""
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


@app.delete("/api/scans/{run_id}", dependencies=[Depends(auth.get_current_user)])
async def cancel_scan(run_id: str):
    """Signal a running scan to stop by closing its queue."""
    if run_id in _active_queues:
        await _active_queues[run_id].put(None)
        _active_queues.pop(run_id, None)
        return {"cancelled": True}
    return {"cancelled": False, "note": "scan not active"}


# ── UI ────────────────────────────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
async def serve_ui():
    html = (Path(__file__).parent / "static" / "index.html").read_text()
    return HTMLResponse(html)


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import uvicorn
    config.RUNS_DIR.mkdir(parents=True, exist_ok=True)
    config.REPOS_DIR.mkdir(parents=True, exist_ok=True)
    uvicorn.run("harness:app", host=config.HOST, port=config.PORT, reload=False)
