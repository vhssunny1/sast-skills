Scan a Python repository for security vulnerabilities by reasoning about data flow — sources, paths, sinks, and sanitization gaps. Write structured findings to findings.json.

Do NOT pattern-match against a checklist of known bugs. Reason from first principles: what data enters each function, where does it go, and what could an attacker do if they controlled it?

## Input

`$ARGUMENTS` format: `[--crawl <path>]`

- `--crawl <path>` — path to `crawl-output.json` (default: `./crawl-output.json`)

---

## Step 1 — Load crawl manifest

Read `crawl-output.json`. Extract `repo_path`, `files[]`, `framework`. If missing, print an error and stop.

---

## Step 1.5 — Load CPG taint hints (if available)

Check if `cpg-output.json` exists in the current directory.

**If absent or `"available": false`:** skip silently. Proceed with standard LLM discovery.

**If `"available": true`:** load the CPG and apply. Check for `"degraded": true` first — if present, `taint_paths[]`/`unreachable_sinks[]` are always empty (a known upstream Joern limitation — see `harness/scripts/joern_extract.sc`'s header comment). In that case `sinks_found[]` is the populated signal; the steps below use whichever arrays are non-empty without special branching.

### 1.5a — Boost file priorities by CPG hit count

Build a per-file hit count from **both** `taint_paths[]` (source_file/sink_file, if non-empty) and `sinks_found[]` (file, if non-empty — a sink location with no traced source, still real CPG signal). Boost `security_priority` in the crawl manifest:
- ≥ 5 combined hits → max(existing, 5)
- 2–4 combined hits → max(existing, 4)
- 1 combined hit → max(existing, 3)

### 1.5b — Load call graph

Store `call_graph[]` as `CPG_CALL_GRAPH` (callee_file + callee_method → callers list).
During Step 4 analysis, check `CPG_CALL_GRAPH` before reading additional files to resolve callers.

### 1.5c — Pre-populate CPG candidates

For each entry in `taint_paths[]` (full traced flow): create a pre-candidate with `cpg_guided: true, cpg_source_confirmed: true`.
For each entry in `sinks_found[]` not already covered by a `taint_paths[]` hit at the same file+line (the primary signal in degraded mode): create a lighter pre-candidate — `sink_file`, `sink_line`, `sink_type` only, no traced source — with `cpg_guided: true, cpg_source_confirmed: false`; you still must find and confirm the source yourself.
Do NOT write to `findings.json` yet — confirm semantics via LLM file read in Step 4b first. Preserve `cpg_guided`/`cpg_source_confirmed` through to `findings.json` in Step 6 — `validate-findings`/`scan-report` read them.

### 1.5d — Mark unreachable sinks

Load `unreachable_sinks[]` (always empty in degraded mode). Annotate matching files in the scan queue with `cpg_reachable: false`.
Still analyze these files (CPG has false negatives for dynamic dispatch / decorators), but mark findings from them accordingly.

Print:
```
  CPG taint hints loaded: (degraded: <true/false>)
    Taint paths        : <N>
    Sinks found        : <N>
    Call graph edges   : <N>
    Unreachable sinks  : <N>
    Files re-prioritized: <N>
    CPG candidates     : <N> pre-mapped (<N> full traced, <N> sink-only)
```

---

## Step 2 — Build the scan queue

Analyze files in this priority order:

1. `entry_point` files (routers, views, API handlers)
2. `middleware` files
3. `dao` files, `async_worker` files (Celery, RQ, Dramatiq, Huey tasks), `pipeline_worker` files — elevated to tier 3 because workers process user-uploaded content and are high-risk for path traversal, SSRF, and injection
4. `service` files
5. `downloader` files, `file_manager` files — file I/O utilities that process external or user-supplied paths
6. `config`, `util` files

Within each tier, read files in descending `security_priority` order (from crawl-output.json). Priority 5 files (sandbox setup, exec/eval, subprocess) are read before priority 3 files (HTTP calls, file I/O).

**Coverage guarantee:** Every file with `security_priority` ≥ 2 (from crawl-output.json) MUST receive at least one full read and analysis pass, regardless of its role tier. Files are processed tier-by-tier and within-tier by descending `security_priority`, but the scan does NOT stop at any tier boundary — all priority ≥ 2 files are reached. Only priority 1 files (boilerplate, migrations, test fixtures) may be skipped. Track and report `files_attempted` and `files_in_manifest` in the output (see Step 6).

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

**Flask-AppBuilder (FAB):**
- Routes defined via `@expose("/path")` on classes inheriting from `BaseView`, `BaseSupersetView`, `ModelRestApi`, or `RestApi`
- User input from `request.json`, `request.args`, `request.form`, `request.get_json()` — same as Flask
- Auth guard via `@protect()` decorator — if absent on an expose'd method, the endpoint is unauthenticated
- FAB's `self.datamodel.add()`, `self.datamodel.edit()`, `self.datamodel.delete()` methods are ORM sinks

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
| SSRF via host/port helpers | `is_port_open(tainted_host, port)`, `do_ping(tainted_host)`, `socket.connect((tainted_host, port))`, `socket.getaddrinfo(tainted_host, ...)` — SSRF through network utility functions that take host/port separately rather than a full URL | Internal network probe — same risk as URL-based SSRF, harder to spot because the sink is not a `requests.get()` call |
| Credential injection into URL | `f"https://{user}:{token}@{tainted}"` — credentials embedded in attacker-controlled host | Credential exfiltration |
| SQL injection | `db.execute(f"...{tainted}...")`, `cursor.execute("..." + tainted)`, `session.execute(text(f"...{tainted}..."))`, raw string SQL passed to ORM | Data exfiltration, auth bypass |
| Template injection | `render_template_string(tainted)`, `jinja2.Template(tainted).render()`, `env.from_string(tainted)` | Remote code execution via SSTI |
| XSS | `{{ value \| safe }}` in Jinja2 template with user data, `Markup(tainted)` rendered in template | Client-side script execution |
| Insecure deserialization | `pickle.loads(tainted)`, `pickle.load(file_from_user)`, `yaml.load(tainted)` without `Loader=yaml.SafeLoader`, `marshal.loads(tainted)` | Remote code execution |
| Open redirect | `redirect(tainted)`, `RedirectResponse(url=tainted)`, `flask.redirect(tainted)` without URL validation | Phishing, session token theft |
| Auth decision from header | `request.headers.get("x-forwarded-email")` used as identity (not JWT-validated state), `request.headers.get(group_key)` used for group membership/authorization | IDOR, privilege escalation |
| oauth2-proxy group bypass | JWT middleware validates `Header-A` and stores `request.state.user_data`, but separately reads `request.headers.get(groups_key)` for group/role authorization — the two reads are decoupled, so an attacker who passes JWT validation can add `groups: admin` as a plain header and gain privileged access. Pattern: `validated = parse_jwt(request.headers["X-Forwarded-Access-Token"])` ... `request.state.user_groups = headers.get(groups_key)`. Fix: read groups from the validated JWT payload (`data.get(groups_key)`), not from raw headers. | Admin privilege escalation |
| Or-chain identity fallback | `resolved = (request.headers.get("x-forwarded-email") or body.user_email or "")` — falls back to user-controlled form/body field when the authenticated header is absent. The JWT-validated identity at `request.state.user_data["email"]` is ignored. Any authenticated user who omits or strips the proxy header can impersonate arbitrary accounts. | Identity spoofing, IDOR |
| Sensitive data in logs | `logger.info(f"password={password}")`, `logger.debug(token)`, logging JWT or API keys | Credential exposure in log files |
| Sandbox escape | `exec(user_code, restricted_globals, locals)` where `restricted_globals["_getattr_"] = getattr` (real getattr, not `safe_getattr`); also: `restricted_globals["getattr"] = getattr` exposed as a named builtin. When `_getattr_` is real `getattr`, RestrictedPython provides zero isolation — class hierarchy traversal finds `subprocess.Popen` without any `import`. | Full OS command execution from sandboxed user code |
| Async queue taint | `queue.enqueue(func, tainted_arg)` or `task.delay(tainted_arg)` — tainted data is serialized to Redis/broker and executed in a worker process. The worker becomes the effective sink even though it runs in a different process. | Deferred execution of injected data across process boundary |
| Path traversal — extended | `os.readlink(tainted)` without checking the resolved path stays within a base dir; `zipfile.ZipFile.extractall(path)` without iterating members and checking each `member.filename` for `..` or absolute paths (Zip Slip); `glob.glob(tainted_pattern)` where pattern contains `..` or `*`; `os.makedirs(tainted_output_dir)` where output_dir is user-supplied | Read/write arbitrary files, cross-tenant access, Zip Slip |
| Symlink following | `shutil.copy(src, dst)` or `open(path)` where `path` is resolved from a user-uploaded archive or repo that may contain symlinks pointing outside the extraction directory — `os.path.islink()` check absent | Arbitrary host file read from uploaded content |
| CSV / spreadsheet formula injection | `csv.writer.writerow([tainted_field])` in an admin export or report endpoint where `tainted_field` starts with `=`, `+`, `-`, `@` — spreadsheet applications treat these as formulas | Remote code execution via Excel/LibreOffice formula evaluation when admin opens the export |
| YAML injection | `yaml.dump({"key": tainted})` or `yaml.dump(tainted_dict)` where dict keys or values come from user input containing YAML special characters (`{`, `}`, `:`, `\n`) — can break out of intended structure | Malformed YAML written to config or skill files; potential YAML deserialization if re-loaded |
| Cypher injection (Neo4j / graph DB) | `session.run(f"MATCH (n) WHERE n.name = '{tainted}'")`, `graph.query(f"... {tainted} ...")` — string interpolation into Cypher queries | Data exfiltration from graph database, auth bypass |
| NoSQL / query language injection | `collection.find({tainted_key: tainted_value})` where key is user-controlled; LogQL: `f'{{app="myapp"}} \|= "{tainted}"'` in Loki queries; PromQL user-controlled label values | Observability data exfiltration, query bypass |
| Resource exhaustion — unbounded read | `file.read(user_size)` or `file.read()` on a user-uploaded file with no size cap before reading into memory; `response.content` on an HTTP response to a user-controlled URL with no `stream=True` + size limit | Memory exhaustion DoS |
| Resource exhaustion — unbounded loop | `for item in range(user_count):` or `while user_condition:` where upper bound is user-controlled and uncapped | CPU exhaustion DoS |
| Resource exhaustion — ReDoS | `re.compile(user_pattern)` or `re.search(user_pattern, large_input)` where `user_pattern` is supplied directly from request input — catastrophic backtracking on crafted inputs | CPU exhaustion via regex denial of service |
| Resource exhaustion — decompression bomb | `gzip.decompress(user_bytes)` or `zipfile.extractall()` trusting `ZipInfo.file_size` from the archive header (falsifiable) without enforcing a decompressed-size limit | Disk/memory exhaustion |
| Outbound data leakage — response | `return JSONResponse({"error": str(exception)})` — raw exception message (may contain internal paths, stack frames, DB credentials) returned to caller; `response.headers.update(upstream_response.headers)` forwarding internal service headers verbatim to client; `yield f"data: {traceback.format_exc()}"` in SSE stream | Internal system information exposure to external clients |
| Outbound data leakage — logs | `logger.info(f"endpoint={os.environ['OPENAI_ENDPOINT']}")`, `logger.debug(f"token={access_token}")` — cloud service credentials or auth tokens written to stdout/log files unconditionally | Credential exposure in log aggregation systems |
| Application-code supply chain | `urllib.request.urlretrieve(url, local_path)` or `requests.get(url, stream=True)` + `open(local_path, "wb").write(...)` followed by `os.chmod(local_path, 0o755)` + `subprocess.run([local_path, ...])` — binary downloaded from an external URL (GitHub release, CDN) and executed without cryptographic hash verification. Also: `subprocess.run(["pip", "install", git_plus_url])` where git_plus_url contains a branch name instead of a commit SHA (e.g. `git+https://github.com/org/repo@main`). | Supply-chain code execution — a compromised CDN or mutable git ref delivers a backdoored binary that runs with the application's privileges |

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

**Q2 — Authorization and Ownership (IDOR):** Does this function perform a privileged operation (accessing another user's data, admin action)?

*Part A — Identity source:* Is the identity check based on JWT-validated state (`request.state.user_data`) or on a raw HTTP header (`request.headers.get(...)`)? Raw header = auth bypass risk.

*Part B — Ownership verification (IDOR):* Does this function accept a resource identifier (`project_id`, `session_id`, `doc_id`, `item_id`, or any `*_id` / `*_uuid` path or body parameter) and then perform a DB fetch, update, or delete on that identifier?

If yes, check: is the resource's owner field compared against the authenticated caller's identity at any point before or after the DB operation?

**Ownership IS verified if:**
- `if resource.owner_email != request.state.user_data["email"]: raise HTTPException(403)`
- ORM query filtered by owner: `.filter(Project.id == id, Project.owner == caller)`
- Explicit ownership helper called: `check_ownership(resource_id, caller)` that raises on mismatch

**Ownership is NOT verified if:**
- Only an authentication check exists: `if not request.state.user_data: raise 401` — being logged in ≠ owning this resource
- Only a role check exists: `if "admin" not in groups` — role ≠ ownership of a specific resource instance
- Resource is fetched and returned with no check at all

Flag as IDOR (CWE-639) when a resource ID parameter is accepted, a DB operation uses it, and no ownership comparison exists. Severity: critical for destructive operations (delete, bulk delete); high for write/read of private per-user data; medium for non-sensitive cross-tenant read.

**Q3 — Crypto:** Does this function hash or compare passwords/tokens? Is the algorithm appropriate (bcrypt, argon2, PBKDF2 via passlib)? Is MD5 or SHA1 used for passwords?

**Q4 — Sensitive data in logs:** Does this function log passwords, tokens, secrets, or PII?

**Q5 — File handling:** Does this function construct file paths from user input? Is there a `resolve()` + `relative_to()` guard?

Additional sink variants to check for, beyond simple read-path traversal:
- `os.path.join()` where any component comes from user input, even if sanitized upstream — check whether the sanitization handles null bytes, unicode normalization, and `../` encoding variants, not just a literal `../` string match
- `open(user_filename, 'w')` — arbitrary file **write**, not just read; often missed because path-traversal review defaults to read-only sinks
- `shutil.copy`/`shutil.move` with a user-controlled source or destination
- `zipfile.ZipFile.extractall()` without verifying each member's resolved path stays within the target directory (Zip Slip, CWE-22) — a crafted archive entry named e.g. `../../etc/cron.d/x` writes outside the intended extraction folder

**Q6 — Security library trust model:** Does this function set up or invoke a security library (RestrictedPython, `advocate` for SSRF, `bleach` for XSS, etc.)? If yes:
1. Look up what the library requires to provide its stated protection (e.g. RestrictedPython requires `_getattr_ = safe_getattr`, `advocate` must replace `requests` consistently).
2. Check whether the code installs ALL the required guards — not just the obvious ones.
3. Flag any guard that is weakened, replaced with the real builtin, or simply absent.
4. Pay special attention to named builtins exposed alongside guards: `builtins["getattr"] = getattr` allows the same bypass via function-call form even if the guard is otherwise set correctly.

**Q7 — Env-gated feature flags:** Does this function activate a dangerous code path only when an environment variable is set (e.g. `if settings.REMOTE_USER_LOGIN_ENABLED:`)? If yes, report a conditional finding with a `condition` field. These are real vulnerabilities — the condition just scopes when they are exploitable.

**Q9 — JWT middleware authorization split:** When you find a middleware or auth layer that (a) validates a JWT and stores the payload in `request.state` or `g`, AND (b) also reads a separate header for group/role authorization — verify that BOTH reads come from the same validated source. The group/role read is dangerous if it uses `request.headers.get(...)` instead of the already-validated state object. Even if JWT validation is solid, reading groups from a separate raw header completely bypasses it.

Also look for or-chain identity resolution: `resolved_email = (header_value or body.email or "")`. Any or-chain that falls back to a user-supplied body field is a bypass when the first term is absent. The fix is to use only the JWT-validated state: `request.state.user_data.get("email")`.

**General JWT validation gaps** (broader than the middleware-split pattern above — check every `jwt.decode()`/`jwt.verify()` call site, not just auth middleware):
- `jwt.decode()` called without verifying `exp`, `aud`, or `iss` claims (check the `options=` dict for `verify_exp: False` etc., or a library default that skips one of these)
- Algorithm confusion: decoding with `algorithms=["HS256", "RS256"]` (both accepted) instead of a single explicit algorithm — allows an attacker who obtains the RS256 public key to forge an HS256-signed token using that key as the HMAC secret
- A symmetric signing secret read from an environment variable with a weak hardcoded default (`os.environ.get("JWT_SECRET", "changeme")`)
- Token accepted via a URL query parameter — ends up in server access logs, browser history, and referrer headers

**Q8 — Defense exists but not called:** When you identify an SSRF, path traversal, open redirect, or SQL sink with no sanitization visible in the current file, scan the `files[]` list from `crawl-output.json` for utility files (`utils/`, `helpers/`, `lib/`) that contain functions named `is_safe_host`, `validate_url`, `check_host`, `allowed_redirect`, `safe_path`, `validate_scheme`, or similar. If such a function exists elsewhere in the codebase but is NOT called at the vulnerable sink:
- Confirm the finding as real (the developer knew the risk and wrote a guard, but forgot to wire it)
- Add to `sanitization_gaps`: "Safety function `<name>` exists in `<file>` but is not called at this sink — calling it would fix this."
- Set confidence 0.95 (existence of a named guard function is strong evidence the sink was known to be dangerous)

This pattern — "defense written but not deployed" — is one of the most exploitable SSRF/redirect classes because the fix is a single function call.

**Q10 — Outbound data leakage into responses or logs:** Does this function return sensitive system information in HTTP responses or write it to logs unconditionally?

Look for:
- `str(exception)` or `traceback.format_exc()` in a returned response body or SSE stream — exposes internal paths, DB connection strings, stack frames
- `response.headers.update(upstream.headers)` — forwards internal service headers (auth tokens, trace IDs, internal hostnames) verbatim to the client
- `os.environ.get("SECRET")` or `settings.INTERNAL_ENDPOINT` included in a JSON response field
- `logger.info(f"... {token} ...")` or `logger.debug(credentials)` — cloud API keys, OAuth tokens, or DB passwords written to log output unconditionally (not just in debug mode)
- Internal file paths or server hostnames in response headers (e.g. `X-Log-Path: /var/log/app/prod.log`)

Flag with CWE-209 (information exposure via error message) or CWE-532 (sensitive information in log files).

**Q11 — Dead defensive code (security function never wired up):** Does this module define a security-relevant function that is never called on any production code path?

Look for:
- Functions named `sanitize_*`, `validate_*`, `guardrail_*`, `check_*`, `filter_*`, `is_safe_*`, `redact_*` defined in the file
- Check whether each such function has callers anywhere in the codebase (search `files[]` from crawl-output.json for the function name)
- If the function is defined but has zero production callers (only tests, or nowhere), flag it: the developer identified the risk and implemented the fix but never wired it up

This is high-signal: flag at medium severity with confidence 0.90. The fix is always a single function call at the unprotected site.

**Q12 — Resource exhaustion (user controls computation bounds):** Does user input control the size, count, or complexity of a computation with no enforced upper limit?

Look for:
- `file.read(user_size)` or `read_bytes(n=user_n)` with no cap
- `for _ in range(user_count):` with no `min(user_count, MAX)` guard
- `re.search(user_pattern, corpus)` — user supplies the regex, not just the input string (ReDoS)
- `zipfile.ZipFile.extractall()` where total extracted size is not tracked against a limit
- `gzip.decompress(data)` or `bz2.decompress(data)` without a decompressed-size cap (decompression bomb)
- `image_extract(user_video, max_frames=None)` — unbounded media processing
- **Falsy size guard bypass:** `if not size: size = DEFAULT_MAX` — Python's `not` is truthy/falsy, so `size=0` (a valid user-supplied value) bypasses the guard entirely. Always use `if size is None:` for guard checks. When reviewing size guards, check whether the guard uses `if not x:` or `if x is None:` — only the latter is safe.

Flag as CWE-400 (uncontrolled resource consumption) at medium severity. Sanitization: `min(user_value, SAFE_MAX)` or explicit size cap before the operation.

**In-memory collections without eviction:** dicts/sets/lists used as session registries, caches, or queues where entries are added on user action but never pruned. Look for: a global dict/set at module level, `.append()`/`.update()` called per-request or per-connection, no max-size check, no TTL, no cleanup on disconnect/session-end. Flag as CWE-400 — an attacker who can trigger repeated entries (new sessions, new connections) grows the collection unboundedly.

**Q13 — System-wide data access without authorization gate:** For every route/endpoint handler, distinct from Q2 (which requires a `*_id` parameter + DB op with no owner filter — this question covers system-scoped data with no resource ID to trace at all):

a. Does the handler return or mutate data that spans multiple users or the entire system (logs, analytics, all-project listings, bulk deletions, admin operations)?
b. Is there NO ownership check AND no auth decorator/dependency at the handler level? (Look for: missing `@require_auth`, missing `current_user` param, missing tenant filter in the query)
c. Confirm: is the data returned user-scoped or system-scoped?

Flag if: handler touches system-scoped data + no auth gate of any kind. Severity: High-Critical depending on data sensitivity. CWE-862 (Missing Authorization).

**Q14 — Runtime binary download patterns in Python source:** Distinct from Q8 (which is about an existing guard function not being called at a sink) — this is about missing integrity verification on downloaded/executed code, which may have no guard function anywhere in the codebase to find. Scan for:

a. `requests.get`/`urllib`/`httpx` downloading an executable, then writing to disk and executing it without verifying a SHA-256 or GPG signature
b. Pattern: fetch URL → write bytes → `os.chmod(..., 0o755)` → `subprocess.run`/`os.execv`
c. Binary files (`.whl`, `.so`, `.exe`) committed to the repository and referenced directly (check `files[]` from `crawl-output.json` for binary paths referenced in import statements or load calls)
d. A "download manager" class pattern (e.g. a `download_asset()`-style method) with no integrity check before use

Flag each: file, line range, what binary is fetched, what an attacker controlling the download source could substitute. CWE-494 (Download of Code Without Integrity Check), CWE-829 (Inclusion of Functionality from Untrusted Control Sphere).

**Q15 — Mass assignment:** Does a handler pass a request body/dict directly into an ORM write with no field allowlist? Look for `Model.objects.create(**request.POST.dict())` (Django), `Model(**request.form)` / `Model(**request.get_json())` (Flask-SQLAlchemy), `for k, v in data.items(): setattr(user, k, v)`, or a DRF serializer with `fields = "__all__"` and no `read_only_fields` excluding privilege columns (`is_staff`, `is_superuser`, `role`, `balance`). Confirm the model/serializer doesn't already restrict writable fields before flagging. CWE-915, high severity when the writable field set includes anything privilege-related.

**Q16 — CSRF protection absent on state-changing routes:** For POST/PUT/PATCH/DELETE views that authenticate via a session cookie (Django's default `SessionMiddleware`+cookie auth, or Flask session cookies — not a bearer-token API where the client sets `Authorization` manually), check whether CSRF protection is actually applied: Django's `@csrf_exempt` on a state-changing view, or a Flask view registered without `@csrf.protect` / `WTF_CSRF_ENABLED` context when the app uses Flask-WTF elsewhere. Flag `@csrf_exempt` on a state-changing view as CWE-352, medium-high depending on impact. (Global `CSRF_ENABLED=false` is already caught by `config-audit`'s env-file check — this question catches the code-level per-view exemption instead.)

**Don't be fooled by a nearby origin/referer check that doesn't gate anything:** some handlers read `request.headers.get('Origin')`/`Referer` right next to the sensitive write and it can look like protection at a glance. Verify the check's result is actually used in a conditional that returns/raises when it fails. If the boolean is instead passed to unrelated bookkeeping (a metrics call, an internal challenge/analytics tracker) and the write below it runs unconditionally regardless of that boolean's value, there is no real protection — flag it exactly as if no check existed. Read the full surrounding function; do not stop at "a check mentioning origin/referer exists somewhere in this handler."

**Q17 — Cookie and security-header hardening:** This check requires an explicit search, not incidental noticing — a file can get read for an unrelated finding (a hardcoded key, a weak hash) and a `set_cookie(...)` call nearby is easy to skip past. As a discrete sub-step, search the whole codebase for every `response.set_cookie(...)`/`HttpResponse.set_cookie(...)` call site, not just files already flagged for other reasons. For each: is it setting a session/auth/CSRF token? If so and `secure=True`, `httponly=True`, or `samesite="Lax"/"Strict"` are missing or explicitly `False` — including a call with no keyword flags at all, which is the same as all three being absent — flag as CWE-614.

Separately, check the app's entry-point/middleware setup for which of these specific headers are actually configured: `Content-Security-Policy`, `Strict-Transport-Security`, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy` (via `flask-talisman`, a custom `after_request` handler, or equivalent). This is a per-header check, not all-or-nothing — an app can set some of these while still lacking CSP or HSTS entirely. Flag CWE-693 medium severity per specific header class that is absent, noting exactly which headers are covered vs missing so the fix is targeted, not a blanket "add headers" note that ignores partial coverage already in place.

**Q18 — Weak cryptography and randomness (beyond Q3's password-hash check):** Does the file use `hashlib.md5()`/`hashlib.sha1()` for a token, signature, or integrity check (not a non-security checksum/cache key) — flag as CWE-327. Does `random.random()`, `random.randint()`, or `random.choice()` generate a session id, password-reset token, or API key instead of the `secrets` module (`secrets.token_urlsafe()`, `secrets.token_hex()`) — flag as CWE-330. Is an encryption key passed to `Fernet(key)` / `AES.new(key, ...)` a string literal in source rather than loaded from env/secret store — flag as CWE-321.

**Q19 — Timing side-channels and user enumeration:** In a login or password-reset view, does the response differ (status code, message text) depending on whether the *account* exists vs. whether the *password* is wrong (e.g. `if not user: return 404` vs. a separate `if not check_password(): return 401`)? Both branches should return an identical generic response — flag as CWE-204/CWE-208. Separately, is a secret/token compared with `==` instead of `hmac.compare_digest()` or `secrets.compare_digest()` — flag as CWE-208 at medium severity (lower confidence than enumeration, since network-timing exploitation is harder in practice).

**Q20 — Password policy and re-authentication on change:** Does the registration or password-set endpoint accept any non-empty string with no minimum length/complexity validation (no Django `AUTH_PASSWORD_VALIDATORS` equivalent check applied, or a Pydantic/marshmallow field with no length/regex constraint)? Flag as CWE-521 medium severity (distinct from CWE-916, which is about hash algorithm strength, not policy). **Check both places this validation could live, not just the route/view:** ORM-heavy apps often push field-level rules into the model layer — a SQLAlchemy/Django model's custom setter/property that hashes the password but applies no length/complexity check anywhere is just as much a missing-policy finding as an empty view function. If the view passes the raw password straight to a model create/update call with no validation on either side, trace into that model file before concluding whether policy exists. Does the password-change endpoint update the password without first verifying the current password or a fresh re-auth token? Flag as CWE-620 high severity — a hijacked session can otherwise permanently lock out the real account owner.

**Q21 — Sensitive data at rest and in URL:** Does a model/ORM write store a field that should be encrypted/hashed (SSN, credit card, raw password, private API key) as plaintext with no transform applied before `.save()`/`.commit()` — flag as CWE-312. Separately, does a password, session token, or password-reset token appear as a URL path/query parameter (`request.GET.get("token")` used for a reset link, rather than a POST body) — flag as CWE-598; query strings land in server access logs, browser history, and `Referer` headers sent to third parties.

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
| IDOR / missing ownership check | CWE-639 | A01:2021 |
| Improper authorization | CWE-285 | A01:2021 |
| Missing auth for critical function | CWE-306 | A07:2021 |
| Sensitive data in logs | CWE-532 | A09:2021 |
| Weak password hash | CWE-916 | A02:2021 |
| CSV / spreadsheet formula injection | CWE-1236 | A03:2021 |
| NoSQL / graph / observability query injection | CWE-943 | A03:2021 |
| YAML injection | CWE-94 | A03:2021 |
| Resource exhaustion / DoS | CWE-400 | A05:2021 |
| ReDoS | CWE-1333 | A05:2021 |
| Decompression bomb | CWE-409 | A05:2021 |
| Information exposure via error message | CWE-209 | A09:2021 |
| Information exposure in logs | CWE-532 | A09:2021 |
| Zip Slip (archive path traversal) | CWE-22 | A01:2021 |
| Symlink following | CWE-59 | A01:2021 |
| Application-code supply chain (download without integrity check) | CWE-494 | A08:2021 |
| Mass assignment (unrestricted field write) | CWE-915 | A08:2021 |
| CSRF protection absent (per-view exemption) | CWE-352 | A01:2021 |
| Cookie missing Secure/HttpOnly/SameSite | CWE-614 | A05:2021 |
| Missing security headers | CWE-693 | A05:2021 |
| Weak crypto algorithm (MD5/SHA1 for tokens) | CWE-327 | A02:2021 |
| Insufficiently random token (random module) | CWE-330 | A02:2021 |
| Hardcoded server-side crypto key | CWE-321 | A02:2021 |
| Timing side-channel / user enumeration | CWE-204 | A07:2021 |
| Weak password requirements | CWE-521 | A07:2021 |
| Unverified password change | CWE-620 | A07:2021 |
| Cleartext storage of sensitive data | CWE-312 | A02:2021 |
| Sensitive data in query parameters | CWE-598 | A01:2021 |

**CVSS 3.1 scoring** — For every finding, assign `cvss_vector` and `cvss_score`.

Choose each of the 8 metric values based on this finding's specific attack path:

| Metric | Values | Meaning |
|---|---|---|
| AV (Attack Vector) | N/A/L/P | Network / Adjacent / Local / Physical |
| AC (Attack Complexity) | L/H | Low (reliable exploit) / High (special conditions needed) |
| PR (Privileges Required) | N/L/H | None / Low (any authenticated user) / High (admin) |
| UI (User Interaction) | N/R | None / Required (victim must take an action) |
| S (Scope) | U/C | Unchanged (same security domain) / Changed (cross-component) |
| C (Confidentiality) | H/L/N | High (full read) / Low (partial) / None |
| I (Integrity) | H/L/N | High (full write) / Low (partial) / None |
| A (Availability) | H/L/N | High (full DoS) / Low (degraded) / None |

Use the reference table below to pick a starting vector, then adjust for the specific finding:

| Vulnerability class | Base vector | Score |
|---|---|---|
| RCE — network, no auth | CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H | 9.8 |
| RCE — network, auth required | CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H | 8.8 |
| SQL injection — no auth | CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N | 9.1 |
| SQL injection — auth required | CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N | 8.1 |
| NoSQL / graph / observability injection — auth | CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N | 8.1 |
| SSRF — no auth | CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N | 7.5 |
| SSRF — auth required | CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N | 6.5 |
| Template injection (SSTI) — no auth | CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H | 9.8 |
| Template injection (SSTI) — auth required | CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H | 8.8 |
| Insecure deserialization (pickle) — no auth | CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H | 9.8 |
| IDOR — read, auth required | CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N | 6.5 |
| IDOR — write/delete, auth required | CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N | 8.1 |
| Auth bypass — header-based identity | CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N | 9.1 |
| Open redirect — no auth | CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N | 6.1 |
| Path traversal — read, auth required | CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N | 6.5 |
| Path traversal — write, auth required | CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N | 8.1 |
| Hardcoded secret — network exploitable | CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N | 9.1 |
| Weak password hash (MD5/SHA1) | CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N | 5.9 |
| Supply chain (download without integrity check) | CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H | 9.0 |
| CSV formula injection — auth, requires UI | CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:H | 8.0 |
| Prompt injection (indirect, LLM-mediated) | CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N | 4.8 |
| Information leakage — error messages | CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N | 5.3 |
| Resource exhaustion / ReDoS | CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H | 7.5 |
| Mass assignment — privilege field writable | CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N | 7.7 |
| CSRF — state-changing view, session auth | CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N | 6.5 |
| Cookie missing Secure/HttpOnly flag | CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N | 4.3 |
| Missing security headers | CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N | 4.7 |
| Weak crypto / predictable token (random module) | CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N | 6.5 |
| Timing side-channel / user enumeration | CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N | 5.3 |
| Weak password requirements | CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N | 4.0 |
| Unverified password change | CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N | 6.8 |
| Cleartext storage of sensitive data | CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:N/A:N | 5.5 |

Adjustment examples:
- Exploit requires admin access → PR:L → PR:H (score drops ~0.5–2.0)
- Special conditions needed (race, specific config) → AC:L → AC:H
- Vulnerability only exploitable locally → AV:N → AV:L
- Auth bypass finding is conditional on a feature flag → AC:L → AC:H

`cvss_score` must be consistent with `severity`: Critical 9.0–10.0, High 7.0–8.9, Medium 4.0–6.9, Low 0.1–3.9. If your vector places a finding outside the severity band, prefer the vector and note the discrepancy in `confidence_note`.

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
  "files_attempted": 42,
  "files_in_manifest": 45,
  "findings_by_severity": { "critical": 0, "high": 0, "medium": 0, "low": 0 },
  "findings": [
    {
      "id": "FINDING-001",
      "cwe": "CWE-918",
      "owasp": "A10:2021",
      "severity": "high",
      "confidence": 0.93,
      "confidence_note": "",
      "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
      "cvss_score": 6.5,
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
  "files_skipped": [
    { "path": "migrations/env.py", "reason": "security_priority 1 — boilerplate" }
  ],
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
  Files attempted : <N> / <total_in_manifest> (<skipped> skipped — priority 1 only)
  Findings      : <total> (<critical> critical / <high> high / <medium> medium / <low> low)
  Output        : findings.json
```
