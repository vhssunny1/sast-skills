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

## Using the Web UI

### 1. Open the browser

Navigate to `http://localhost:8000`

### 2. Log in

Enter the username (`admin` by default) and the password you set in `HARNESS_PASSWORD`.

### 3. Start a scan

Paste a Git repository URL into the **Git repository URL** field:

```
https://github.com/juice-shop/juice-shop.git
https://github.com/your-org/your-repo.git
```

Select any options:

| Option | What it does |
|---|---|
| Skip taint-trace | Faster scan, higher false-positive rate |
| Skip config-audit | Skip .env / Dockerfile / CI file scanning |
| Generate DAST tests | Also output a `dast-tests.py` script |
| Force fresh | Ignore any incomplete prior run — always start from step 1 |

Click **Scan**. The repo is cloned automatically.

### 4. Watch live progress

The progress panel shows each pipeline step in real time:

```
✓  detect-language      — TypeScript + Python | polyglot: yes
⟳  crawl-python         — read_file: requirements.txt
⟳  crawl-typescript     — read_file: package.json
⟳  config-audit         — running...
—  (Group 1 concurrent — all three run at the same time)

✓  find-vulns-python    — 12 findings
✓  find-vulns-typescript — 8 findings
—  (Group 2 concurrent)

✓  taint-trace          — 17 confirmed / 3 denied
✓  validate-findings    — 18 confirmed / 2 suppressed
✓  scan-report          — scan-results.sarif + scan-summary.md
```

### 5. Download results

When the scan completes, the **Downloads** panel appears:

| File | Contents |
|---|---|
| `scan-summary.md` | Human-readable report with all findings, CVSS scores, fix hints |
| `scan-results.sarif` | SARIF 2.1.0 — open in VS Code or upload to GitHub Security tab |
| `findings-final.json` | Full findings JSON with taint paths and validation scores |
| `findings-validated.json` | Findings after FP scoring, before final enrichment |
| `run-log.json` | Structured per-step audit log — timing, findings delta, errors |
| `dast-tests.py` | DAST test script (only if Generate DAST tests was checked) |

### 6. View scan history

The left sidebar lists all prior scans with their status. Click any entry to view its step breakdown and re-download its results.

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
