Map a Python repository for downstream SAST analysis. Classifies Python files by role, identifies HTTP entry points and routes, and writes crawl-output.json.

Called by sast-full-scan when detect-language identifies Python as a significant language.

## Input

`$ARGUMENTS` format: `<repo-path> [--include-tests]`

- `<repo-path>` — absolute or relative path to the repository root
- `--include-tests` — if omitted, test files are excluded

---

## Step 1 — Collect files

Walk `<repo-path>` recursively. Collect `.py` files.

Exclude these directories entirely:
`.git/`, `__pycache__/`, `.venv/`, `venv/`, `env/`, `.env/`, `node_modules/`, `build/`, `dist/`, `.mypy_cache/`, `.pytest_cache/`

Exclude test files unless `--include-tests` is passed:
- Files under any directory named `test/`, `tests/`, `testing/`
- Files whose name starts with `test_` or ends with `_test.py`

If total `.py` count exceeds 400:
- List top 5 directories by file count
- Ask user to confirm or narrow the path before continuing

---

## Step 2 — Classify each Python file by role

Scan the first 120 lines for markers. Apply the FIRST matching role:

| Role | Markers |
|---|---|
| `entry_point` | `@router.get`, `@router.post`, `@router.put`, `@router.delete`, `@router.patch`, `@app.get`, `@app.post`, `@app.put`, `@app.delete`, `@app.patch`, `APIRouter()`, file is directly in a directory named `routers/`, `api/`, `views/` |
| `middleware` | `BaseHTTPMiddleware`, `@app.middleware`, file named `*middleware*`, `*auth*`, `*security*`, `*interceptor*`; class inheriting from `BaseHTTPMiddleware` or `Middleware` |
| `async_worker` | **Celery:** `@celery.task`, `@app.task`, `@shared_task`; **RQ:** `Queue.enqueue`, `@job` from rq, `rq.job` imported, `.enqueue(`, file in `jobs/`; **Dramatiq:** `@dramatiq.actor`; **Huey:** `@huey.task`; file in `tasks/`, `workers/`, `jobs/` |
| `dao` | `Session`, `AsyncSession`, `db.query(`, `db.execute(`, `select(`, `insert(`, `update(`, `delete(` from sqlalchemy, `cursor.execute(`, `pymysql`, `psycopg2`, file in `repositories/`, `repository/`, OR file in `models/` with DB operation imports |
| `model` | `class.*BaseModel\(`, `class.*Base\(`, Pydantic `BaseModel` subclasses, SQLAlchemy declarative base subclasses, `@dataclass`, file in `schemas/`, `models/` without DB operations |
| `service` | File in `services/`, `service/`, `components/`; class/function names ending in `Service`, `Manager`, `Processor`, `Handler`, `Orchestrator` |
| `config` | File named `config*`, `settings*`, `constants*`, `env*`; `BaseSettings` from pydantic; `os.environ` or `os.getenv` used for loading configuration |
| `util` | Everything else |

---

## Step 3 — Extract routes from entry_point files

For each entry_point file, read the full file and extract all route decorators:

```python
# Pattern: @router.METHOD("path") or @app.METHOD("path")
@router.get("/projects/{project_id}")
async def get_project(...):
```

Extract:
- HTTP method (get, post, put, delete, patch)
- Path string (first positional string argument in the decorator)
- Function name immediately below the decorator
- Path parameters in the route string (e.g. `{project_id}`)

For Django views: extract URL patterns from `urls.py` files — `path("route/", view_function)` or `re_path(r"pattern", view_function)`.

For Flask blueprints: extract `@bp.route("/path", methods=["GET", "POST"])`.

---

## Step 4 — Detect framework and dependencies

Check these files in order (first found wins):
1. `requirements.txt` (and `requirements/*.txt`)
2. `pyproject.toml` — `[project].dependencies` or `[tool.poetry.dependencies]`
3. `Pipfile`
4. `setup.py`

**Framework detection:**
- `fastapi` in deps → `fastapi`
- `flask` in deps → `flask`
- `django` in deps → `django`
- `starlette` only → `starlette`
- None → `unknown`

**Python version:** from `pyproject.toml` `requires-python`, or `.python-version` file, or `runtime.txt`.

**Security-sensitive packages to flag:**
`PyJWT`, `cryptography`, `paramiko`, `pexpect`, `subprocess32`, `requests`, `httpx`, `aiohttp`, `gitpython`, `GitPython`, `celery`, `rq`, `dramatiq`, `huey`, `RestrictedPython`, `pickle` (in imports), `pyyaml`/`PyYAML`, `python-multipart`, `python-jose`

**Config files to also read** (for dangerous-defaults detection — do NOT skip):
- `.env` / `*.env` at repo root and `docker/` — flag `DEBUG=true`, `TESTING=true`, feature flags enabled (e.g. `REMOTE_USER_LOGIN_ENABLED=true`), or secrets that look like defaults (`secret`, `changeme`, `sast-test`)
- `docker-compose.yml` / `compose.yaml` — flag ports bound to `0.0.0.0`, `skip_frontend_build` or `FLASK_ENV=development`, and backend ports exposed alongside a proxy
- `settings*.py` / `config*.py` — flag `DEBUG = True`, `ALLOWED_HOSTS = ["*"]`, `SECRET_KEY` set to a short/guessable string

Add a `config_warnings[]` array to the output for any dangerous defaults found.

---

## Step 5 — Write crawl-output.json

Write to `crawl-output.json` in the current working directory. Overwrite if exists.

```json
{
  "repo_path": "<absolute path>",
  "scanned_at": "<ISO 8601 timestamp>",
  "language": "python",
  "languages_detected": ["python"],
  "runtime_version": "3.11",
  "framework": "fastapi",
  "total_files": 0,
  "entry_points": [
    {
      "path": "backend/src/api/routers/project.py",
      "role": "entry_point",
      "routes": [
        { "method": "GET", "path": "/projects", "handler": "get_projects" },
        { "method": "POST", "path": "/projects", "handler": "create_project" }
      ]
    }
  ],
  "files": [
    {
      "path": "backend/src/api/routers/project.py",
      "role": "entry_point",
      "lines": 240,
      "language": "python",
      "security_priority": 3
    }
  ],
  "dependencies": [
    { "name": "fastapi", "version": "0.111.0", "security_sensitive": false },
    { "name": "gitpython", "version": "3.1.41", "security_sensitive": true },
    { "name": "PyJWT", "version": "2.9.0", "security_sensitive": true }
  ],
  "skipped_files": [],
  "warnings": [],
  "config_warnings": [
    "REMOTE_USER_LOGIN_ENABLED=true in .env — feature-flag gated auth bypass when backend port is directly reachable",
    "Secret key matches known test/default value in .env"
  ]
}
```

---

## Constraints

- Skip files exceeding 5000 lines — add to `skipped_files` with reason `exceeds line limit`
- Skip binary files — add to `skipped_files` with reason `binary`
- Role detection reads only the first 120 lines; route extraction reads the full file
- If a file matches multiple roles (e.g. has both `@router.get` and `BaseHTTPMiddleware`), apply the first match in the table order above — entry_point takes priority over middleware

## Security priority scoring (per file)

While reading the first 120 lines for role classification, also assign `security_priority` (1–5) based on dangerous patterns seen:

| Score | Indicators |
|---|---|
| 5 | `exec(`, `eval(`, `subprocess`, `RestrictedPython`, sandbox setup (`restricted_globals`), `_getattr_`, `_setattr_` |
| 4 | `request.headers.get(`, `REMOTE_USER`, feature-flag reads (`os.getenv("..._ENABLED")`), `pickle`, `yaml.load` |
| 3 | `requests.get(`, `httpx`, DB query construction, `open(`, `os.path.join` |
| 2 | DB model definitions, serializers, standard business logic |
| 1 | Pure data classes, constants, type stubs |

`find-vulns-python` reads files in descending `security_priority` order within each role tier.

---

## Completion

```
crawl-python complete.
  Repo          : <repo-path>
  Framework     : <framework> (Python <version>)
  Files         : <N> .py files mapped
  Entry points  : <N> routes across <N> router files
  Middleware    : <N> files
  Services      : <N> files
  DAOs          : <N> files
  Async workers : <N> files (Celery / RQ / Dramatiq / Huey)
  High-priority : <N> files with security_priority ≥ 4
  Flagged deps  : <list>
  Config warnings: <N> dangerous defaults found
  Output        : crawl-output.json
```
