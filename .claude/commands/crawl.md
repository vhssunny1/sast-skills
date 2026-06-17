Map a repository for downstream SAST analysis. Auto-detects language, classifies files by role, identifies entry points, and writes structured output to crawl-output.json.

## Input
$ARGUMENTS format: `<repo-path> [--include-tests]`

- `<repo-path>` — absolute or relative path to the repository root
- `--include-tests` — optional flag; if omitted, test files are excluded from output

If no argument is provided, use the current working directory as repo-path.

---

## Phase 1 — Language Detection

1. Verify `<repo-path>` exists. If not, print an error and stop.

2. Walk the entire directory tree (excluding `.git/`, `node_modules/`, `__pycache__/`, `target/`, `build/`, `dist/`, `out/`, `.venv/`, `venv/`).

3. Count files by extension:

   | Extension group | Language |
   |---|---|
   | `.java`, `.jsp`, `.jspx` | Java |
   | `.py` | Python |
   | `.ts`, `.tsx` | TypeScript |
   | `.js`, `.jsx` | JavaScript |
   | `.go` | Go |
   | `.rb` | Ruby |
   | `.cs` | C# |
   | `.php` | PHP |

4. Identify the **primary language**: the one with the most source files. If two languages each have ≥ 20% of total source files, treat the repo as **polyglot** and crawl both.

5. Print a detection summary before proceeding:
   ```
   Language Detection
     Python  : 968 files  ← PRIMARY
     TypeScript: 76 files
     YAML    : 54 files (config, skipped)
   Proceeding with: Python + TypeScript (polyglot)
   ```

6. Branch to the language-specific crawl phase below based on detected language(s).

---

## Phase 2A — Python Crawl (primary language: Python)

### Files to collect
Collect all `.py` files. Also note `.yaml`/`.yml`/`.toml`/`.env*`/`.ini` for config context.

### Exclude unless `--include-tests`
- Files under any directory named `test/`, `tests/`, `testing/`
- Files whose name starts with `test_` or ends with `_test.py`

### If total `.py` file count exceeds 400
- Print a warning listing the top 5 directories by file count
- Ask the user to confirm or provide a narrower path before continuing

### Role classification for each `.py` file

Scan the first 120 lines for markers:

| Role | Markers to look for |
|---|---|
| `entry_point` | `@router.get`, `@router.post`, `@router.put`, `@router.delete`, `@router.patch`, `@app.get`, `@app.post`, `@app.put`, `@app.delete`, `@app.patch`, `APIRouter()`, file is in `routers/` or `api/` directory |
| `service` | File is in `controller/`, `service/`, `services/`, `components/` with business logic; class/function names ending in `Service`, `Manager`, `Processor`, `Handler`, `Orchestrator` |
| `dao` | `Session`, `db.query`, `db.execute`, `SQLAlchemy`, `AsyncSession`, file in `repositories/`, `repository/`, `models/` with DB access; `select(`, `insert(`, `update(`, `delete(` from sqlalchemy |
| `model` | `class.*BaseModel`, `class.*Base(`, Pydantic model definitions, dataclass definitions, file in `models/`, `schemas/` |
| `filter_interceptor` | `@app.middleware`, `Middleware`, FastAPI `Depends(` in security context, `HTTPBearer`, `OAuth2`, file named `middleware*`, `auth*`, `security*`, `interceptor*` |
| `config` | File named `config*`, `settings*`, `env*`, `constants*`; `BaseSettings` from pydantic; environment variable loading |
| `celery_task` | `@celery.task`, `@app.task`, `@shared_task`, file in `tasks/`, `workers/`; `celery` import |
| `util` | Everything else |

### Extract routes for entry_point files
For each `entry_point` file, extract:
- Decorator method: `get`, `post`, `put`, `delete`, `patch`
- Path string from the decorator (first positional string argument)
- Function name immediately below the decorator

### Framework and runtime detection
- Check `pyproject.toml`, `requirements.txt`, `setup.py`, `Pipfile` for:
  - FastAPI → `framework: fastapi`
  - Flask → `framework: flask`
  - Django → `framework: django`
  - Starlette only → `framework: starlette`
  - LangChain/LangGraph present → note in `notes` field
- Extract Python version from `pyproject.toml` (`requires-python`) or `.python-version`

### Dependencies
Parse `pyproject.toml` `[project].dependencies` or `requirements.txt`. Extract name + pinned version. Flag security-sensitive packages: `PyJWT`, `cryptography`, `paramiko`, `pexpect`, `subprocess32`, `requests`, `httpx`, `aiohttp`.

---

## Phase 2B — TypeScript/JavaScript Crawl (primary or secondary language)

### Files to collect
Collect `.ts`, `.tsx`, `.js`, `.jsx` files. Exclude `node_modules/`, `dist/`, `build/`, `.next/`, `coverage/`.

### Exclude unless `--include-tests`
- Files under `__tests__/`, `*.test.ts`, `*.spec.ts`, `*.test.tsx`, `*.spec.tsx`

### Role classification for each file

Scan the first 120 lines:

| Role | Markers to look for |
|---|---|
| `entry_point` | `App.tsx`, `main.tsx`, `index.tsx`, React Router `<Route`, `createBrowserRouter`, Next.js `pages/` or `app/` directory |
| `service` | Filename ends in `.service.ts`, `*Api.ts`, `*Client.ts`; `axios.`, `fetch(`, `useQuery`, `useMutation` with API calls |
| `dao` | Direct API fetch wrappers, RTK Query `createApi`, GraphQL query files |
| `model` | TypeScript `interface`, `type`, `enum` definitions; files in `types/`, `models/`, `interfaces/` |
| `filter_interceptor` | Auth guards, route protection HOCs, context providers wrapping auth (`AuthContext`, `ProtectedRoute`) |
| `config` | `*.config.ts`, environment imports (`import.meta.env`, `process.env`), constants files |
| `util` | Utility functions, formatters, helpers |

### Extract routes for entry_point files
For React Router / Next.js: extract path strings from `<Route path=`, `createBrowserRouter` path keys, or Next.js file-based route paths.

### Framework detection
- Detect React, Next.js, Vue, Angular, Svelte from `package.json` dependencies
- Extract Node version from `.nvmrc` or `engines` field in `package.json`

### Dependencies
Parse `package.json` `dependencies` and `devDependencies`. Flag security-sensitive packages: `jsonwebtoken`, `axios`, `node-fetch`, `ws`, `socket.io`, `express`, `helmet` (absence is a flag), `dompurify` (absence with dangerouslySetInnerHTML is a flag).

---

## Phase 2C — Java Crawl (primary language: Java)

### Files to collect
Collect `.java`, `.jsp`, `.jspx`, `.xml`, `.properties`, `.yml`, `.yaml`.

### Exclude unless `--include-tests`
- Files under `test/` or `it/`
- Files ending in `Test.java`, `Tests.java`, `IT.java`, `Spec.java`

### If total `.java` file count exceeds 300
- Print a warning listing the top 5 directories by file count
- Ask the user to confirm or provide a narrower path before continuing

### Role classification for each `.java` file

Scan the first 100 lines:

| Role | Markers to look for |
|---|---|
| `entry_point` | `@Controller`, `@RestController`, `@RequestMapping`, `extends HttpServlet`, `@Path` (JAX-RS) |
| `service` | `@Service`, `implements *Service`, `@Component` with business logic |
| `dao` | `@Repository`, `extends JpaRepository`, `extends CrudRepository`, `EntityManager`, `JdbcTemplate` |
| `model` | `@Entity`, `@Table`, plain POJO with only fields + getters/setters |
| `filter_interceptor` | `implements Filter`, `implements HandlerInterceptor`, `extends OncePerRequestFilter` |
| `config` | `@Configuration`, `@EnableWebSecurity`, `SecurityConfig` |
| `util` | Everything else |

### Extract routes for entry_point files
HTTP method annotations (`@GetMapping`, `@PostMapping`, `@PutMapping`, `@DeleteMapping`, `@RequestMapping`), route paths, method names.

### Framework and runtime detection
Parse `pom.xml` or `build.gradle`:
- Java version
- Framework: Spring Boot, Spring MVC, Struts, JSF, JAX-RS, or unknown
- Direct dependencies (groupId:artifactId:version)

---

## Output Schema

Write to `crawl-output.json` in the current working directory (overwrite if exists).

```json
{
  "repo_path": "<absolute path>",
  "scanned_at": "<ISO 8601 timestamp>",
  "language": "python | typescript | java | polyglot",
  "languages_detected": ["python", "typescript"],
  "runtime_version": "3.11",
  "framework": "fastapi | flask | django | spring-boot | spring-mvc | react | nextjs | unknown",
  "notes": ["LangChain detected", "Celery task queue detected"],
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
      "role": "entry_point | service | dao | model | filter_interceptor | config | celery_task | util",
      "lines": 120,
      "language": "python"
    }
  ],
  "dependencies": [
    { "name": "fastapi", "version": "0.111.0", "security_sensitive": false },
    { "name": "PyJWT", "version": "2.9.0", "security_sensitive": true }
  ],
  "skipped_files": [
    { "path": "...", "reason": "exceeds line limit | binary | unreadable" }
  ],
  "warnings": []
}
```

---

## Constraints

- Skip any file exceeding 5000 lines — add to `skipped_files` with reason `exceeds line limit`
- Skip binary files — add to `skipped_files` with reason `binary`
- Do not read file contents beyond what is needed for classification (first 120 lines is sufficient for role detection)
- For polyglot repos, include files from all detected primary languages in the single `files` array; use the per-file `language` field to distinguish them

---

## Downstream consumers

- `/find-vulns` reads `entry_points` and `files` to prioritize and scope analysis
- `/taint-trace` reads `files` grouped by role to build the call graph
- `/sast-full-scan` passes `crawl-output.json` path to all subsequent skills

---

## Completion

Print a summary in this format:
```
Crawl complete.
  Repo        : <repo-path>
  Language    : <language> (<framework>)
  Files       : <total_files> files mapped
  Entry points: <count> routes across <n> router files
  Services    : <count> files
  DAOs        : <count> files
  Models      : <count> files
  Sec-sensitive deps: <list of flagged packages>
  Output      : crawl-output.json
```
