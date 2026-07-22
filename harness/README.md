# SAST Harness — Usage Guide

A FastAPI web server that runs the SAST pipeline as an agentic service. Point it at any Git repository URL and get a full scan with live progress streaming, downloadable reports, and auto-resume on failure.

---

## Prerequisites

- Python 3.11+
- Git (must be on PATH)
- An Anthropic API key

---

## Installation

```bash
# from the sast-skills repo root
cd harness
pip install -r requirements.txt
```

---

## Configuration

All settings are controlled by environment variables. Set them before starting the server.

| Variable | Required | Default | Description |
|---|---|---|---|
| `ANTHROPIC_API_KEY` | **yes** | — | Your Anthropic API key |
| `HARNESS_PASSWORD` | **yes** | `changeme` | Password for web login — change this |
| `HARNESS_USERNAME` | no | `admin` | Login username |
| `JWT_SECRET` | no | *(insecure default)* | Secret used to sign session tokens — change in production |
| `SAST_MODEL` | no | `claude-sonnet-4-6` | Claude model to use for all skills |
| `HARNESS_HOST` | no | `0.0.0.0` | Server bind address |
| `HARNESS_PORT` | no | `8000` | Server port |
| `MAX_SKILL_ITERATIONS` | no | `60` | Max tool-call loops per skill before timing out |

### Minimal setup (Windows PowerShell)

```powershell
$env:ANTHROPIC_API_KEY = "sk-ant-..."
$env:HARNESS_PASSWORD  = "your-secure-password"
$env:JWT_SECRET        = "your-random-secret-string"
```

### Minimal setup (bash/zsh)

```bash
export ANTHROPIC_API_KEY="sk-ant-..."
export HARNESS_PASSWORD="your-secure-password"
export JWT_SECRET="your-random-secret-string"
```

---

## Starting the server

```bash
# from the sast-skills repo root
python harness/harness.py
```

The server starts on `http://localhost:8000` by default.

```
INFO:     Started server process
INFO:     Uvicorn running on http://0.0.0.0:8000
```

---

## Accessing from the web browser

### Same machine

Open your browser and go to:

```
http://localhost:8000
```

### From another machine on the same network

Find the IP address of the machine running the harness:

```powershell
# Windows
ipconfig
# look for IPv4 Address under your active adapter e.g. 192.168.1.42
```

```bash
# macOS / Linux
hostname -I   # or: ifconfig | grep "inet "
```

Then open on any browser on any device on the same network:

```
http://192.168.1.42:8000
```

Share this URL with teammates — they can log in and trigger scans from their own browser without installing anything.

### Changing the port

If port 8000 is taken, set a different one before starting:

```powershell
# Windows PowerShell
$env:HARNESS_PORT = "9000"
python harness/harness.py
# → accessible at http://localhost:9000
```

```bash
# bash/zsh
HARNESS_PORT=9000 python harness/harness.py
```

---

## Using the Web UI

### Step 1 — Open the browser

Navigate to `http://localhost:8000` (or the network URL above if accessing from another machine).

### Step 2 — Log in

You will see a login screen. Enter:
- **Username**: `admin` (or whatever you set in `HARNESS_USERNAME`)
- **Password**: the value you set in `HARNESS_PASSWORD`

Click **Sign in**. Your session lasts 24 hours before you need to log in again.

### Step 3 — Paste a Git URL and start a scan

In the **Git repository URL** field, paste the HTTPS or SSH URL of any repo:

```
https://github.com/juice-shop/juice-shop.git
https://github.com/your-org/your-private-repo.git
git@github.com:your-org/your-repo.git
```

> **Note:** For private repos over HTTPS, include credentials in the URL:
> `https://username:token@github.com/org/repo.git`
> For SSH, make sure the server's SSH key is added to your Git host.

Choose scan options if needed:

| Option | When to use |
|---|---|
| Skip taint-trace | Quick pass — trades accuracy for speed (~40% faster) |
| Skip config-audit | Repo has no .env / Dockerfile / CI files |
| Generate DAST tests | You want a `dast-tests.py` script to run against the live app |
| Force fresh | Previous incomplete run exists but you want to start over |

Click **Scan**. The harness clones the repo automatically (or pulls latest if already cloned) and starts the pipeline.

### Step 4 — Watch live progress

The progress panel updates in real time as each skill runs. You do not need to refresh the page.

```
✓  detect-language       TypeScript + Python | polyglot: yes
⟳  crawl-python          read_file: requirements.txt          ← currently running
⟳  crawl-typescript      read_file: package.json              ← running concurrently
⟳  config-audit          running...                           ← running concurrently

✓  find-vulns-python     12 findings
✓  find-vulns-typescript  8 findings

✓  taint-trace           17 confirmed / 3 denied
✓  validate-findings     18 confirmed / 2 suppressed
✓  scan-report           scan-results.sarif + scan-summary.md
```

Icons:
- `⟳` — currently running
- `✓` — completed
- `—` — skipped (single-language repo, or flag was set)
- `✗` — failed (scan can be resumed next run)

### Step 5 — Download results

When the scan completes, a **Downloads** section appears at the bottom of the progress panel:

| File | What it contains |
|---|---|
| **Markdown report** | `scan-summary.md` — all findings with CVSS scores, evidence, and fix hints. Open in any Markdown viewer. |
| **SARIF 2.1.0** | `scan-results.sarif` — import into VS Code (SARIF Viewer extension) or upload to GitHub Security tab under your repo's Security → Code scanning. |
| **findings.json** | Full findings with taint paths, validation scores, CVSS vectors. Machine-readable. |
| **Validated findings** | Findings after false-positive scoring, before final merge. |
| **Run log** | `run-log.json` — per-step timing, findings delta, errors. Useful for debugging a slow or failed scan. |
| **DAST test script** | `dast-tests.py` — only present if **Generate DAST tests** was checked. Run it against the live app: `python dast-tests.py` |

Click any link to download directly to your machine.

### Step 6 — View past scans

The **left sidebar** lists every scan run, newest first. Each entry shows:
- Run ID (timestamp)
- Repository name
- Status badge: `complete` / `failed` / `running`

Click any entry to view its step-by-step breakdown and re-download its result files. Useful when you want to compare two scans of the same repo.

### Step 7 — Cancel a running scan

While a scan is in progress, a **Cancel** button appears in the top-right of the progress panel. Clicking it stops the scan. The partial results are saved — the next run of the same repo will auto-resume from where it left off.

---

## Auto-resume

If a scan fails or the server restarts mid-scan, the harness automatically detects the incomplete run the next time you scan the **same repository URL**:

```
Incomplete run detected: 20260722-103045  (failed at: taint-trace)
Resuming from taint-trace — skipping completed steps.
To start fresh instead: re-run with Force fresh checked
```

Completed steps are skipped. The last good findings snapshot is restored automatically. No data is lost.

---

## REST API

The harness exposes a REST API — useful for CI/CD integration.

### Login

```bash
curl -X POST http://localhost:8000/api/auth/login \
  -d "username=admin&password=your-password"
# → { "access_token": "eyJ...", "token_type": "bearer" }

TOKEN="eyJ..."
```

### Start a scan

```bash
curl -X POST http://localhost:8000/api/scans \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "git_url": "https://github.com/juice-shop/juice-shop.git",
    "skip_taint": false,
    "skip_config_audit": false,
    "dast": false,
    "fresh": false
  }'
# → { "run_id": "20260722-103045" }
```

### Stream live progress (SSE)

```bash
curl -N "http://localhost:8000/api/scans/20260722-103045/stream?token=$TOKEN"
# streams newline-delimited JSON events:
# data: {"type":"step_start","step":"detect-language"}
# data: {"type":"step_complete","step":"detect-language","findings_after":null}
# data: {"type":"pipeline_complete","run_id":"...","total_findings":24}
```

### Get scan status

```bash
curl http://localhost:8000/api/scans/20260722-103045 \
  -H "Authorization: Bearer $TOKEN"
# → full run-log.json content
```

### List all scans

```bash
curl http://localhost:8000/api/scans \
  -H "Authorization: Bearer $TOKEN"
# → array of scan summaries sorted newest first
```

### Download a result file

```bash
curl -O http://localhost:8000/api/scans/20260722-103045/files/scan-summary.md \
  -H "Authorization: Bearer $TOKEN"
```

Available filenames: `scan-summary.md`, `scan-results.sarif`, `findings-final.json`, `findings-validated.json`, `run-log.json`, `dast-tests.py`

### Cancel a running scan

```bash
curl -X DELETE http://localhost:8000/api/scans/20260722-103045 \
  -H "Authorization: Bearer $TOKEN"
```

---

## Output directory layout

Each scan writes to `sast-runs/<run-id>/`:

```
sast-runs/
└── 20260722-103045/
    ├── run-log.json               ← per-step audit log (timing, findings delta, errors)
    ├── language-manifest.json     ← language + framework detection
    ├── crawl-output.json          ← merged file map (all languages)
    ├── findings-after-config-audit.json
    ├── findings-raw.json          ← candidates from find-vulns
    ├── findings-traced.json       ← after taint-trace
    ├── findings-validated.json    ← after FP scoring
    ├── findings-final.json        ← final findings (copy of findings.json)
    ├── scan-results.sarif         ← SARIF 2.1.0
    ├── scan-summary.md            ← human report
    ├── dast-tests.py              ← (only if --dast)
    └── workdir/                   ← live working directory during scan
```

Cloned repos are stored in `sast-repos/<repo-name>/` and reused across scans (pulled to latest on each run).

---

## Troubleshooting

**`git clone failed`** — check the URL is correct and the server has network access. For private repos, use SSH URLs and ensure the server's SSH key has repo access.

**Skill times out** — increase `MAX_SKILL_ITERATIONS` (default 60). Large repos with many files may need 80–100.

**`ANTHROPIC_API_KEY` not set** — the server starts but all scans fail at the first skill. Set the env var and restart.

**Port already in use** — set `HARNESS_PORT=8001` (or any free port) and restart.

**Resume not triggering** — auto-resume matches on exact `repo_path` (the local clone path). If the clone path changed, use the **Force fresh** option.
