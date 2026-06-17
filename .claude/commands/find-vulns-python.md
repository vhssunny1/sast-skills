Scan a Python repository for security vulnerabilities by reasoning about data flow — sources, paths, sinks, and sanitization gaps. Write structured findings to findings.json.

Do NOT pattern-match against a checklist of known bugs. Reason from first principles: what data enters each function, where does it go, and what could an attacker do if they controlled it?

## Input

`$ARGUMENTS` format: `[--crawl <path>]`

- `--crawl <path>` — path to `crawl-output.json` (default: `./crawl-output.json`)

---

## Step 1 — Load crawl manifest

Read `crawl-output.json`. Extract `repo_path`, `files[]`, `framework`. If missing, print an error and stop.

---

## Step 2 — Build the scan queue

Analyze files in this priority order:

1. `entry_point` files (routers, views, API handlers)
2. `middleware` files
3. `dao` files
4. `service` files
5. `async_worker` files (Celery, RQ, Dramatiq, Huey tasks)
6. `config`, `util` files

Within each tier, read files in descending `security_priority` order (from crawl-output.json). Priority 5 files (sandbox setup, exec/eval, subprocess) are read before priority 3 files (HTTP calls, file I/O).

---

## Step 3 — Sources, sinks, and sanitization

### Sources (attacker-controlled data)

**FastAPI:**
- `Form(...)`, `Query(...)`, `Path(...)`, `Body(...)`, `Header(...)` — function parameters decorated with these are user-controlled
- `request.headers.get("header-name")` — raw HTTP headers
- `request.query_params.get("key")` — URL query string
- `UploadFile.filename` — user-supplied filename on file upload

**Flask:**
- `request.args.get("key")` — query string
- `request.form.get("key")` — POST form body
- `request.json` / `request.get_json()` — JSON body fields
- `request.headers.get("header-name")` — raw HTTP headers
- `request.cookies.get("key")` — cookies (user-controlled)

**Django:**
- `request.GET.get("key")`, `request.POST.get("key")`
- `request.data` (DRF) — request body
- `request.headers.get("key")` — raw headers
- `kwargs["pk"]` / URL kwargs from `urls.py`

**Common across frameworks:**
- Any URL path parameter bound to a function argument
- JSON body fields (when body is parsed and fields used without validation)
- Values loaded from DB that were originally user-supplied (check if the column is user-writable)

Taint propagates through: function arguments, return values, variable assignment, string formatting (`f"..."`, `.format()`, `%`), dict/list access on tainted containers.

### Sinks (dangerous operations)

| Sink | Examples | Risk |
|---|---|---|
| Command injection | `subprocess.run([..., tainted])`, `subprocess.run(tainted, shell=True)`, `subprocess.call()`, `subprocess.Popen()`, `os.system(tainted)`, `os.popen(tainted)`, `os.execv()` | Remote code execution |
| Code injection | `eval(tainted)`, `exec(tainted)` | Remote code execution |
| Path traversal | `open(tainted)`, `open(os.path.join(base, tainted))` without resolve guard, `shutil.copy(tainted, ...)`, `shutil.move(tainted, ...)`, `os.makedirs(tainted)`, `pathlib.Path(tainted).read_text()` | Read/write arbitrary files |
| SSRF | `requests.get(tainted)`, `requests.post(tainted)`, `httpx.get(tainted)`, `aiohttp.ClientSession().get(tainted)`, `urllib.request.urlopen(tainted)`, `Repo.clone_from(tainted, ...)` | Internal network probe, metadata theft |
| Credential injection into URL | `f"https://{user}:{token}@{tainted}"` — credentials embedded in attacker-controlled host | Credential exfiltration |
| SQL injection | `db.execute(f"...{tainted}...")`, `cursor.execute("..." + tainted)`, `session.execute(text(f"...{tainted}..."))`, raw string SQL passed to ORM | Data exfiltration, auth bypass |
| Template injection | `render_template_string(tainted)`, `jinja2.Template(tainted).render()`, `env.from_string(tainted)` | Remote code execution via SSTI |
| XSS | `{{ value \| safe }}` in Jinja2 template with user data, `Markup(tainted)` rendered in template | Client-side script execution |
| Insecure deserialization | `pickle.loads(tainted)`, `pickle.load(file_from_user)`, `yaml.load(tainted)` without `Loader=yaml.SafeLoader`, `marshal.loads(tainted)` | Remote code execution |
| Open redirect | `redirect(tainted)`, `RedirectResponse(url=tainted)`, `flask.redirect(tainted)` without URL validation | Phishing, session token theft |
| Auth decision from header | `request.headers.get("x-forwarded-email")` used as identity (not JWT-validated state), `request.headers.get(group_key)` used for group membership/authorization | IDOR, privilege escalation |
| Sensitive data in logs | `logger.info(f"password={password}")`, `logger.debug(token)`, logging JWT or API keys | Credential exposure in log files |
| Sandbox escape | `exec(user_code, restricted_globals, locals)` where `restricted_globals["_getattr_"] = getattr` (real getattr, not `safe_getattr`); also: `restricted_globals["getattr"] = getattr` exposed as a named builtin. When `_getattr_` is real `getattr`, RestrictedPython provides zero isolation — class hierarchy traversal finds `subprocess.Popen` without any `import`. | Full OS command execution from sandboxed user code |
| Async queue taint | `queue.enqueue(func, tainted_arg)` or `task.delay(tainted_arg)` — tainted data is serialized to Redis/broker and executed in a worker process. The worker becomes the effective sink even though it runs in a different process. | Deferred execution of injected data across process boundary |

### Sanitization that breaks the chain

- `urlparse(url).scheme in ("https",)` **AND** code raises/returns on mismatch — breaks SSRF
- `Path(user_input).resolve().relative_to(base_path)` — raises `ValueError` on traversal — breaks path traversal
- `subprocess.run(shlex.split(cmd))` is NOT safe if `cmd` is fully user-controlled; `shlex.quote(tainted_arg)` for individual args breaks command injection
- Parameterized SQL: `db.execute(text("SELECT * FROM t WHERE id = :id"), {"id": tainted})`, SQLAlchemy ORM filter methods — breaks SQL injection
- Pydantic field validators that strictly constrain to an allowlist and raise `ValueError` on mismatch — breaks injection if applied before the sink
- `request.state.user_data.get("email")` — identity from JWT-validated middleware state — breaks header-based auth bypass (contrast with `request.headers.get("x-forwarded-email")` which is NOT validated)
- `yaml.safe_load(tainted)` — breaks YAML deserialization
- **Not sanitization:** null/None checks, length limits, `isinstance()` checks that don't constrain content, logging the value

---

## Step 4 — Analyze each Python file

For every file in the scan queue, read the full file, then for each function/method ask:

**Q1 — Taint:** What are the inputs (parameters, HTTP sources)? What sinks are in the body? Does any tainted value reach a sink without effective sanitization?

**Q2 — Authorization:** Does this function perform a privileged operation (accessing another user's data, admin action)? Is the identity check based on JWT-validated state (`request.state.user_data`) or on a raw HTTP header (`request.headers.get(...)`)?

**Q3 — Crypto:** Does this function hash or compare passwords/tokens? Is the algorithm appropriate (bcrypt, argon2, PBKDF2 via passlib)? Is MD5 or SHA1 used for passwords?

**Q4 — Sensitive data in logs:** Does this function log passwords, tokens, secrets, or PII?

**Q5 — File handling:** Does this function construct file paths from user input? Is there a `resolve()` + `relative_to()` guard?

**Q6 — Security library trust model:** Does this function set up or invoke a security library (RestrictedPython, `advocate` for SSRF, `bleach` for XSS, etc.)? If yes:
1. Look up what the library requires to provide its stated protection (e.g. RestrictedPython requires `_getattr_ = safe_getattr`, `advocate` must replace `requests` consistently).
2. Check whether the code installs ALL the required guards — not just the obvious ones.
3. Flag any guard that is weakened, replaced with the real builtin, or simply absent.
4. Pay special attention to named builtins exposed alongside guards: `builtins["getattr"] = getattr` allows the same bypass via function-call form even if the guard is otherwise set correctly.

**Q7 — Env-gated feature flags:** Does this function activate a dangerous code path only when an environment variable is set (e.g. `if settings.REMOTE_USER_LOGIN_ENABLED:`)? If yes, report a conditional finding with a `condition` field. These are real vulnerabilities — the condition just scopes when they are exploitable.

---

## Step 5 — Score, deduplicate, assign IDs

**Confidence:**
- 0.90–1.00 — source and sink in same function, direct taint, no sanitization visible
- 0.70–0.89 — one hop of reasoning (parameter passes through one call before reaching sink)
- 0.50–0.69 — indirect path, cross-file, sanitization may exist in a layer not yet read
- < 0.50 — discard

**Filter:** ≥ 0.70 report; 0.50–0.69 report with `confidence_note: "indirect path — verify manually"`.

**Deduplicate:** same CWE + same file + same line ±3 → keep higher confidence.

**Number:** `FINDING-001`, `FINDING-002`, ...

**CWE/OWASP mapping:**

| Class | CWE | OWASP |
|---|---|---|
| SQL injection | CWE-89 | A03:2021 |
| Command injection | CWE-78 | A03:2021 |
| Code injection (eval/exec) | CWE-94 | A03:2021 |
| XSS / template injection | CWE-79 | A03:2021 |
| Server-Side Template Injection | CWE-1336 | A03:2021 |
| SSRF | CWE-918 | A10:2021 |
| Path traversal | CWE-22 | A01:2021 |
| Credential exposure via URL | CWE-522 | A02:2021 |
| Insecure deserialization | CWE-502 | A08:2021 |
| Unvalidated redirect | CWE-601 | A01:2021 |
| Insecure auth (header-based) | CWE-287 | A01:2021 |
| Improper authorization | CWE-285 | A01:2021 |
| Missing auth for critical function | CWE-306 | A07:2021 |
| Sensitive data in logs | CWE-532 | A09:2021 |
| Weak password hash | CWE-916 | A02:2021 |

---

## Step 6 — Write findings.json

Write to `findings.json` in the current working directory. Overwrite if exists.

```json
{
  "scanned_at": "<ISO 8601>",
  "repo_path": "<absolute path>",
  "language": "python",
  "crawl_input": "./crawl-output.json",
  "total_findings": 0,
  "findings_by_severity": { "critical": 0, "high": 0, "medium": 0, "low": 0 },
  "findings": [
    {
      "id": "FINDING-001",
      "cwe": "CWE-918",
      "owasp": "A10:2021",
      "severity": "high",
      "confidence": 0.93,
      "confidence_note": "",
      "file": "backend/src/utils/git/git_util.py",
      "line": 32,
      "method": "clone_git_repo",
      "source": "git_url — user-supplied repo_url from POST /v2/projects form body",
      "sink": "Repo.clone_from(git_url, ...) — GitPython initiates network connection to arbitrary URL",
      "sanitization_present": "none — only max_length=300 check on input model",
      "evidence": "repo = Repo.clone_from(git_url, local_folder_location, branch=branch_name, depth=1)",
      "description": "The repo_url form field flows through multiple layers to Repo.clone_from() with no URL scheme or host validation. Attackers can supply file://, http://internal-host/, or git:// URLs to probe internal networks.",
      "fix_hint": "Validate URL scheme before calling Repo.clone_from(): parsed = urlparse(git_url); if parsed.scheme not in ('https',): raise ValueError(...)",
      "condition": null
    }
  ],
  "skipped_files": [],
  "warnings": []
}
```

---

## Hard rules

- Report only what you can see in the code you read. Do not invent findings.
- `evidence` must be the verbatim line from the file (leading whitespace trimmed only).
- `source` must name the specific variable or call introducing user-controlled data.
- `sink` must name the specific dangerous operation.
- Do not consult ground truth files, CVE lists, or prior knowledge of this codebase. Findings must come from reading the code.
- For sandbox escape findings: cite the specific line where `_getattr_` or `getattr` is installed in the restricted globals dict. The vulnerability is in the guard installation, not the `exec()` call itself.
- `condition` field: set to a human-readable string when the vulnerability is only exploitable under a specific runtime condition (e.g. `"REMOTE_USER_LOGIN_ENABLED=true"`). Set to `null` for unconditional findings. Never omit the field.

---

## Completion

```
find-vulns-python complete.
  Repo          : <repo_path>
  Files scanned : <N> Python files
  Findings      : <total> (<critical> critical / <high> high / <medium> medium / <low> low)
  Output        : findings.json
```
