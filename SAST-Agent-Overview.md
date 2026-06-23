# LLM-Powered SAST Agent — Complete Overview

## What This Is

A fully prompt-driven Static Application Security Testing (SAST) pipeline implemented as Claude Code slash commands. There is no compiled code — every skill is a Markdown file in `.claude/commands/` that Claude executes. The pipeline ingests any source repository, reasons about data flow from first principles, and produces industry-standard outputs (SARIF 2.1.0, Markdown reports).

---

## Architecture at a Glance

```
/sast-full-scan  ← ORCHESTRATOR — chains every step below
        │
        ├─ /detect-language      → language-manifest.json
        ├─ /crawl[-java/-python/-typescript]  → crawl-output.json
        ├─ /config-audit         → findings.json (config findings)
        ├─ /find-vulns[-java/-python/-typescript]  → findings.json
        ├─ /cross-language-taint → findings.json (XL-* findings, polyglot only)
        ├─ /taint-trace          → findings.json (enriched in place)
        ├─ /validate-findings    → findings.json (scored + ranked)
        ├─ /scan-report          → scan-results.sarif + scan-summary.md
        ├─ /generate-dast-tests  → dast-tests.py (optional, --dast flag)
        └─ /scan-metrics         → sast-metrics.json (append-only)

Standalone fix tool:
        └─ /generate-fix         → unified diff + explanation + test cases
```

Each skill writes one file consumed by the next. No in-memory state crosses skill boundaries — this is intentional and allows any step to be re-run independently.

---

## Language Support

| Language | Framework Detection | Crawl Skill | Vuln Scan Skill |
|---|---|---|---|
| **Java** | Spring Boot, Spring MVC, Struts, JAX-RS | `/crawl-java` | `/find-vulns-java` |
| **Python** | FastAPI, Flask, Django, Flask-AppBuilder | `/crawl-python` | `/find-vulns-python` |
| **TypeScript / JavaScript** | React, Next.js, Express, Vue, Angular | `/crawl-typescript` | `/find-vulns-typescript` |
| **Polyglot (any combo above)** | Auto-detected | All relevant crawl skills run + merge | All relevant find-vulns skills run + merge |
| Go / Ruby / C# / PHP | Detected (file count) | Generic fallback | Generic fallback (partial coverage) |

**Polyglot mode** automatically activates when two or more languages each account for ≥ 20% of source files. Crawl outputs are merged and finding IDs are namespaced (`JAVA-001`, `PY-001`, `TS-001`) to avoid collisions.

---

## Skill Reference

### 1. `/sast-full-scan` — Pipeline Orchestrator

**What it does:** Chains every other skill in the correct order for any language repo.

**Input:** `<repo-path> [--ground-truth <path>] [--out-dir <path>] [--skip-taint] [--skip-config-audit] [--dast]`

**Steps it runs:**
1. `detect-language` — identifies languages and picks which skills to invoke
2. `crawl` (language-specific) — maps the attack surface
3. `config-audit` — audits configuration files
4. `find-vulns` (language-specific) — identifies candidate vulnerabilities
5. `cross-language-taint` — finds Python→TypeScript stored-XSS paths (polyglot only)
6. `taint-trace` — cross-file verification of every finding
7. `validate-findings` — false-positive scoring and ranking
8. `scan-report` — SARIF + Markdown output
9. `generate-dast-tests` — DAST script (only when `--dast` is passed)

**Outputs written to** `sast-runs/YYYYMMDD-HHMMSS/`:
- `language-manifest.json`, `crawl-output.json`, `findings-raw.json`
- `findings-traced.json`, `findings-validated.json`, `findings-final.json`
- `scan-results.sarif`, `scan-summary.md`, `run-manifest.json`
- `dast-tests.py` (if `--dast` was passed)

**Example invocations:**
```bash
/sast-full-scan dvja --ground-truth dvja-ground-truth.MD
/sast-full-scan my-python-app
/sast-full-scan my-repo --skip-taint          # faster, higher FP rate
/sast-full-scan my-repo --dast                 # also generate DAST test script
```

---

### 2. `/detect-language` — Language & Framework Detection

**What it does:** Counts source files by extension, determines primary and secondary languages, detects frameworks from config files, and writes a routing manifest that tells the orchestrator which skills to invoke.

**Input:** `<repo-path>`

**Output:** `language-manifest.json`

**Detection logic:**
- A language is "significant" if it has ≥ 20% of total source files OR ≥ 15 files
- Reads `pom.xml`, `requirements.txt`, `package.json`, `go.mod`, `pyproject.toml` for framework identification
- Sets `polyglot: true` when two or more significant languages exist

**Frameworks detected:** Spring Boot, Spring MVC, Struts, JAX-RS, FastAPI, Flask, Django, React, Next.js, Express, Vue, Angular, Svelte, Gin, Gorilla Mux

**Languages supported for detection:** Java/Kotlin, Python, TypeScript, JavaScript, Go, Ruby, PHP, C#, C++

---

### 3. `/crawl` — Universal Repository Mapper (Auto-detect)

**What it does:** Walks a repository, classifies every source file by its security-relevant role, extracts HTTP routes from entry points, detects frameworks and runtime versions, and flags security-sensitive dependencies.

**Input:** `<repo-path> [--include-tests]`

**Output:** `crawl-output.json`

**Role classifications assigned to each file:**

| Role | What it means |
|---|---|
| `entry_point` | HTTP controllers, routers, API handlers — where user data enters |
| `service` | Business logic layer — transforms and routes data |
| `dao` | Data access — dangerous SQL/ORM sinks often live here |
| `model` | Data model definitions — schemas, entities, Pydantic models |
| `filter_interceptor` | Middleware, auth guards, request interceptors |
| `config` | Configuration and environment variable loading |
| `celery_task` | Async workers (Python: Celery, RQ) |
| `util` | Everything else |

**Language-specific crawl skills:**
- `/crawl-java` — collects `.java`, `.jsp`, `.jspx`, `.xml`, `.properties`; detects Spring/Struts/JAX-RS
- `/crawl-python` — collects `.py`; detects FastAPI/Flask/Django/Flask-AppBuilder; flags `security_priority` per file
- `/crawl-typescript` — collects `.ts`, `.tsx`, `.js`, `.jsx`; detects React/Next.js/Express/Vue

**Security-sensitive dependency flagging:**
- Java: lists all Maven/Gradle dependencies
- Python: flags `PyJWT`, `cryptography`, `paramiko`, `subprocess32`, `requests`, `httpx`
- TypeScript: flags absence of `helmet` and `dompurify` alongside dangerous sinks

---

### 4. `/config-audit` — Configuration Security Audit

**What it does:** Reads only configuration files (no source code) and finds dangerous defaults, weak secrets, and enabled security-bypass flags. Classifies each finding by deployment context to reduce false positives from example files.

**Input:** `<repo-path>`

**Output:** appends to `findings.json` with `CONFIG-*` IDs

**Files examined:**
- `.env`, `.env.local`, `.env.production`, `.env.development`
- `docker-compose.yml`, `compose.yaml`
- `settings.py`, `config.py`, `constants.py`, `defaults.py`, `secrets.py`
- `application.yml`, `application.properties`
- `appsettings.json`, `*.config.json`

**What it checks:**

| Check | Examples | Risk |
|---|---|---|
| Feature flags enabled | `REMOTE_USER_LOGIN_ENABLED=true`, `DEBUG=true`, `DEV_MODE=1` | Auth bypass, stack trace exposure |
| Weak / placeholder secrets | `SECRET_KEY=changeme`, values < 32 chars, `CHANGE_ME_*` constants | Session forgery, JWT bypass |
| Multi-secret scanning | `GUEST_TOKEN_JWT_SECRET`, `GLOBAL_ASYNC_QUERIES_JWT_SECRET`, websocket `jwtSecret` | Token forgery for all token types |
| Docker port exposure | Backend port mapped to `0.0.0.0` alongside a reverse proxy | Proxy bypass |
| Security features disabled | `CSRF_ENABLED=false`, `SSL_VERIFY=false`, `SESSION_COOKIE_SECURE=false` | CSRF, MITM, session theft |
| Hardcoded source fallbacks | `SECRET_KEY = "CHANGE_ME_..."` in `constants.py` | Unconditional credential leak |

**Deployment context classification** (controls false-positive scoring):
- `example_file` — filename contains `example`, `sample`, `template`
- `development_template` — adjacent comment warns "change in production"
- `source_code_fallback` — hardcoded in `.py`/`.ts` source (overrides all template leniency)
- `production_config` — no template signals; treated at full severity

---

### 5. `/find-vulns` / `/find-vulns-java` / `/find-vulns-python` / `/find-vulns-typescript` — Vulnerability Discovery

**What it does:** Reads every source file in priority order (entry points first, then DAOs, then services) and reasons about data flow from first principles. Reports findings only when it can identify a concrete source-to-sink path in the code it reads.

**Hard constraint:** Never pattern-matches against a known-vulnerability checklist. Every finding must be derived from reading the code.

**Input:** `--crawl crawl-output.json`

**Output:** `findings.json`

**Sources (attacker-controlled data) detected by language:**

*Java:* Struts2 setter fields, `request.getParameter()`, `request.getHeader()`, `request.getCookies()`, session attributes set from user input, database values originally user-supplied.

*Python (FastAPI):* `Form(...)`, `Query(...)`, `Path(...)`, `Body(...)`, `Header(...)`, `request.query_params`, `UploadFile.filename`

*Python (Flask):* `request.args.get()`, `request.form.get()`, `request.json`, `request.headers.get()`, `request.cookies.get()`

*Python (Django):* `request.GET.get()`, `request.POST.get()`, `request.data`, `kwargs["pk"]`

*Python (Flask-AppBuilder/Superset):* `@expose()` routes, `@protect()` absence, `request.json/args/form`, FAB ORM sinks

*TypeScript (React):* `useParams()`, `useSearchParams()`, `location.search`, `window.name`, `document.referrer`, form `onChange` state

*TypeScript (Next.js):* `router.query`, `context.query`, `searchParams`, dynamic route `params`

*TypeScript (Express/Node):* `req.query`, `req.body`, `req.params`, `req.headers`

**Sinks (dangerous operations) detected by language:**

| Sink Category | CWE | Severity |
|---|---|---|
| SQL injection (string concat in query) | CWE-89 | Critical |
| Command injection (`exec`, `ProcessBuilder`, `os.system`, `subprocess`) | CWE-78 | Critical |
| Code injection (`eval`, `exec` on user input) | CWE-94 | Critical |
| Server-side template injection | CWE-1336 | Critical |
| Insecure deserialization (`pickle.loads`, `ObjectInputStream`, unsafe `yaml.load`) | CWE-502 | Critical |
| Sandbox escape (RestrictedPython with real `getattr` in restricted globals) | CWE-94 | Critical |
| SSRF (arbitrary URL to `requests.get`, `Repo.clone_from`, `socket.connect`) | CWE-918 | High |
| DOM / React XSS (`innerHTML`, `dangerouslySetInnerHTML`, `bindPopup`) | CWE-79 | High |
| Open redirect (user-controlled `redirect()`, `window.location`) | CWE-601 | High |
| Auth from raw HTTP header instead of JWT-validated state | CWE-287 | High |
| JWT middleware group bypass (groups read from header, not validated JWT payload) | CWE-285 | High |
| Or-chain identity fallback (identity resolved from body field when header absent) | CWE-285 | High |
| Path traversal (`open(user_input)` without `resolve()`+`relative_to()`) | CWE-22 | High |
| Weak password hash (MD5/SHA1 for passwords) | CWE-916 | Medium |
| Sensitive data in logs (`logger.info(password=...)`) | CWE-532 | Medium |
| Unvalidated redirect | CWE-601 | Medium |
| Missing authorization check / IDOR | CWE-639 | High |
| Prototype pollution (`Object.assign` on user-controlled keys) | CWE-1321 | Medium |
| CSS-as-HTML injection (`styleElement.innerHTML = userCss`) | CWE-79 | High |
| Hardcoded credentials in client bundle | CWE-798 | High |
| Null dereference on user-triggered lookup | CWE-476 | Low |
| Dev/debug mode exposed | CWE-209 | Medium |

**Confidence scoring:**
- `0.90–1.00` — source and sink in same method, direct path, no sanitization visible
- `0.70–0.89` — one hop of reasoning (field set by framework, then used at sink)
- `0.50–0.69` — indirect / cross-file, sanitization may exist in unread layer
- `< 0.50` — discarded

**Special detection patterns (Python):**
- `Defense exists but not called` — finds SSRF guard functions (`is_safe_host`, `validate_url`) that exist in utils but are not wired to the vulnerable sink. Sets confidence 0.95.
- `Env-gated features` — vulnerabilities behind `if settings.FEATURE_ENABLED` are reported with a `condition` field, not discarded.
- `Async queue taint` — taint that crosses Celery/RQ process boundary is traced through the broker hop.

**Special detection patterns (TypeScript):**
- `Catch-true anti-pattern` — URL validation functions whose `catch` block returns `true` bypass the check entirely.
- `Custom sanitizer verification` — reads the body of any function called before an HTML sink to verify it actually escapes `<` and `>`.
- `Session cookie exfiltration via fetch` — `fetch(userControlledUrl, { credentials: 'include' })` sends cookies to attacker server even when CORS blocks the response.
- `Mermaid XSS` — `securityLevel: 'loose'` + `innerHTML = svg` path.

---

### 6. `/cross-language-taint` — Polyglot Stored-XSS Detection

**What it does:** Finds stored-XSS and injection paths that cross language boundaries — specifically Python/Java backend storing user data → TypeScript frontend rendering it without sanitization. Single-language scans miss these flows entirely.

**Input:** `--findings findings.json --crawl crawl-output.json`

**Output:** appends `XL-*` findings to `findings.json`

**Two attack classes found:**

1. **Direct stored-XSS:** User submits data → Python stores to DB → TypeScript renders via `marker.bindPopup()`, `innerHTML`, `dangerouslySetInnerHTML` without `DOMPurify`

2. **LLM prompt injection → stored XSS:** User submits attacker-controlled content → Python LLM pipeline processes it → LLM generates output with injected payload → stored unsanitized → TypeScript renders via `innerHTML` or `mermaid(securityLevel:'loose')`

**Render patterns checked:** Leaflet `bindPopup()`, Mapbox `setHTML()`, `element.innerHTML`, `dangerouslySetInnerHTML`, `v-html`, mermaid with `securityLevel: 'loose'`, catch-handler `innerHTML` injection.

**Cross-language findings are protected from dedup** — they are never merged with adjacent intra-language findings even if CWE and line match, because they represent a distinct attack vector.

---

### 7. `/taint-trace` — Cross-File Taint Verification

**What it does:** Takes every candidate finding from `find-vulns` and verifies the source-to-sink data flow by tracing it hop-by-hop across file boundaries. Converts guesses into confirmed paths (or confirmed false positives).

**Input:** `--findings findings.json --crawl crawl-output.json`

**Output:** enriches `findings.json` in place — adds `taint_confirmed`, `confidence_after_trace`, `taint_path[]`, `sanitization_gaps[]`

**Trace outcomes:**

| Outcome | `taint_confirmed` | `confidence_after_trace` | Meaning |
|---|---|---|---|
| `CONFIRMED` | `true` | 0.90–1.00 | Full source→sink path verified, no effective sanitization |
| `DENIED` | `false` | 0.10–0.30 | Effective sanitization found — likely false positive |
| `PARTIAL` | `null` | 0.50–0.69 | Part of path verified; one hop could not be fully read |
| `UNREACHABLE` | `false` | 0.05 | Method is never called from any mapped entry point |

**Supports async queue paths:** Celery/RQ broker hops are represented as `role: "async_queue"` steps in the taint path, since taint crosses process boundaries.

**Supports conditional guard paths:** Feature-flag-gated code paths get `conditional_protection: true` — they remain real findings; the condition scopes when they are exploitable.

---

### 8. `/validate-findings` — False-Positive Scoring & Ranking

**What it does:** Scores each finding from 0.0 (definitely real) to 1.0 (almost certainly false positive) using an auditable rubric. Works only from `findings.json` — never reads source code.

**Input:** `--findings findings.json`

**Output:** enriches `findings.json` in place — adds `fp_score`, `validation_status`, `validation_notes[]`

**Scoring rubric (selected rules):**

| Condition | FP score impact |
|---|---|
| `taint_confirmed: false` | +0.60 (big FP signal) |
| `taint_confirmed: true` | -0.40 (strong real signal) |
| `confidence_after_trace ≥ 0.90` | -0.20 |
| Cross-file taint path verified (≥ 2 steps) | -0.10 |
| `taint_path` has 0 steps | +0.15 |
| Sink in private method with no caller traced | +0.10 |
| Config finding: `example_file` deployment context | +0.40 |
| Config finding: `source_code_fallback` | -0.20 (overrides template leniency) |

**Validation status thresholds:**

| fp_score | Status | Treatment |
|---|---|---|
| 0.00–0.25 | `confirmed` | Include in report |
| 0.26–0.50 | `likely_real` | Include with note |
| 0.51–0.74 | `needs_review` | Include, flag for manual triage |
| 0.75–1.00 | `likely_fp` | Exclude from default report, kept in JSON |

**Also computes:** `estimated_precision = confirmed / (confirmed + likely_fp)`

---

### 9. `/scan-report` — Reporting (SARIF + Markdown)

**What it does:** Produces two outputs from `findings.json`: a SARIF 2.1.0 file for tooling integration and a human-readable Markdown summary. Computes precision, recall, and F1 when a ground truth file is provided.

**Input:** `--findings findings.json [--ground-truth <path>] [--out-dir <path>]`

**Outputs:** `scan-results.sarif`, `scan-summary.md`

**SARIF output** is valid SARIF 2.1.0 — consumable by GitHub Security tab, VS Code SARIF Viewer, and IDE integrations. Contains:
- `rules[]` — one entry per unique CWE, with help URI to MITRE
- `results[]` — one per finding with location, snippet, source, sink, fix hint
- `artifacts[]` — all scanned files

**Markdown summary** contains:
- Executive summary table (totals by severity, precision estimate, recall)
- Full detail cards for `confirmed` and `likely_real` findings (description, source, sink, evidence, taint path, fix hint)
- Compact table for `needs_review` findings
- Suppressed findings table
- Precision / recall / F1 vs ground truth
- **Security Positive Signals** section — verified sanitizers, existing-but-uncalled guards, framework-level protections

**Precision/Recall matching rule:** A finding is a True Positive if its `cwe` AND `file` basename both match a ground truth entry.

---

### 10. `/generate-dast-tests` — DAST Test Script Generation

**What it does:** Turns confirmed SAST findings into a runnable Python script (`dast-tests.py`) that dynamically confirms each finding against a live application. One test function per finding.

**Input:** `--findings findings.json [--base-url <url>] [--out <path>]`

**Output:** `dast-tests.py` (runnable immediately after `docker compose up`)

**Test templates generated by CWE:**

| CWE | Test approach |
|---|---|
| CWE-521 (weak secret) | Flask: forge session cookie with `itsdangerous`; JWT: forge bearer token with HMAC |
| CWE-918 (SSRF) | POST SSRF payloads (localhost, 169.254.169.254); check if "not allowed" is returned |
| CWE-79 (XSS) | Store `<img src=x onerror=alert(1)>` via write endpoint; report render URL |
| CWE-601 (open redirect) | Test external URL, protocol-relative `//`, and data URI redirect payloads |
| CWE-16 (debug mode) | Request a nonexistent route; check response for `Traceback`, `werkzeug` |
| CWE-284 (port exposure) | Socket connect to exposed port; report if reachable |
| CWE-287 (auth bypass) | Hit endpoint with and without `X-Forwarded-Remote-User` header |

All tests include cleanup steps (delete injected data, restore original values). Config findings are documented as static confirmations at the top of the script.

**Language support:** Python apps (FastAPI, Flask, Django, Superset/Flask-AppBuilder).

---

### 11. `/generate-fix` — Secure Code Fix Generator

**What it does:** Takes a single finding ID, reads the vulnerable source file, and produces a minimal surgical patch: a unified diff, an explanation, and test cases. One finding per invocation.

**Input:** `<finding-id> [--findings <path>]`

**Output:** three artifacts printed inline:
- **Diff** — unified diff format, minimum lines changed
- **Explanation** — what the vulnerability was, what the fix does, caveats
- **Test cases** — one regression test + one security test in pseudocode or the target language

**Fix strategies by CWE:**

| CWE | Fix approach |
|---|---|
| CWE-89 (SQL injection) | Replace string concat with named parameter (`.setParameter()`, `PreparedStatement` `?`) |
| CWE-78 (command injection) | Add strict allowlist regex; reject input on mismatch; do NOT attempt escaping |
| CWE-79 (XSS in JSP) | Replace `<%= expr %>` with `<c:out value="${...}"/>` or `fn:escapeXml()` |
| CWE-601 (open redirect) | Add domain allowlist before redirect; reject non-matching URLs |
| CWE-285 (client-controlled auth) | Remove cookie/header check; replace with server-side session role check |
| CWE-639 (IDOR) | Add ownership check after fetch: `resource.getOwnerId() == sessionUser.getId()` |
| CWE-916 (weak hash) | Replace MD5/SHA1 with BCrypt; update both hash-generation and verification |
| CWE-340 (predictable token) | Replace `MD5(username)` with `SecureRandom` + hex/base64 encoding |
| CWE-532 (sensitive log) | Remove password/token from log statement; keep safe fields |
| CWE-476 (null dereference) | Add null check immediately after lookup, before method call on result |

**Sibling detection:** After generating the fix, scans the rest of the same file for the same vulnerability pattern and lists related findings without auto-fixing them.

---

### 12. `/taint-trace` — (also standalone, see §7)

Already documented above. Can be run independently:
```bash
/taint-trace --findings findings.json --crawl crawl-output.json
```

---

### 13. `/scan-metrics` — Metrics History Tracker

**What it does:** Reads all artifacts from a completed scan run and appends a structured metrics record to `sast-metrics.json` (append-only history). Tracks trends across runs.

**Input:** `--run-dir sast-runs/<timestamp>/`

**Output:** appends to `sast-metrics.json`

**Metrics captured:**

| Category | Fields |
|---|---|
| Operational | `total_duration_seconds`, `steps_completed`, `files_scanned` by language |
| Pipeline | `raw_findings`, `after_taint_trace`, `after_validation`, `attrition_rate`, `taint_confirmation_rate` |
| Quality | `confirmed`, `likely_real`, `needs_review`, `likely_fp`, `estimated_precision`, `recall`, `F1` |
| Severity | `critical`, `high`, `medium`, `low` counts |
| CWE | findings count per CWE |
| Coverage | `files_with_findings / total_files_scanned` |
| Trends (vs prior run) | `finding_delta`, `precision_delta`, `new_cwes`, `resolved_cwes` |

Trends are computed only when at least one prior run exists for the same `repo_path`.

---

## Vulnerability Classes Covered (OWASP Mapping)

| OWASP 2021 | CWEs Detected |
|---|---|
| A01 — Broken Access Control | CWE-285, CWE-287, CWE-306, CWE-639, CWE-601, CWE-22 |
| A02 — Cryptographic Failures | CWE-916, CWE-340, CWE-521, CWE-522, CWE-798, CWE-200 |
| A03 — Injection | CWE-89, CWE-78, CWE-94, CWE-79, CWE-1336, CWE-1321 |
| A05 — Security Misconfiguration | CWE-16, CWE-209, CWE-284, CWE-352, CWE-295 |
| A07 — Auth & Identity Failures | CWE-287, CWE-306, CWE-340 |
| A08 — Insecure Deserialization | CWE-502 |
| A09 — Security Logging Failures | CWE-532 |
| A10 — SSRF | CWE-918 |

---

## Validated Test Targets

| Target | Language | Framework | Findings |
|---|---|---|---|
| **DVJA** (Damn Vulnerable Java Application) | Java | Struts 2 + Spring | GT-01 through GT-12; recall ≥ 0.8 on statically-detectable findings |
| **Redash** | Python | Flask + SQLAlchemy | PY-001 (sandbox escape, CVSS 9.9), PY-004 (auth bypass, CVSS 9.8) — DAST-confirmed |
| **Apache Superset** | Python + TypeScript | Flask-AppBuilder + React | Config findings, XSS paths, JWT secret scanning |

---

## Key Design Decisions

| Decision | Rationale |
|---|---|
| Skills-based (not agent-based) | Sequential skills are debuggable — each output file can be inspected; agents would obscure intermediate state |
| No in-memory state between skills | All cross-skill communication is through files; any step can be re-run without restarting the pipeline |
| Semantic reasoning, not pattern matching | LLM reads code and reasons about data flow; checklist scanning against known CVEs would be a correctness violation |
| Confidence scoring before reporting | Prevents alert fatigue; `validate-findings` makes suppression auditable with explicit `validation_notes` |
| SARIF 2.1.0 output | Integrates with GitHub Security tab, VS Code, and any CI/CD tool that consumes SARIF |
| `generate-fix` is standalone | Fixes are one-finding, one-file surgical patches — never refactors adjacent code |

---

## Quick Reference — Running the Pipeline

```bash
# Full pipeline with precision/recall measurement
/sast-full-scan dvja --ground-truth dvja-ground-truth.MD

# Python/TypeScript polyglot repo (auto-detected)
/sast-full-scan my-fullstack-app

# Fast pass — skip taint trace (higher FP rate)
/sast-full-scan my-repo --skip-taint

# Full pipeline + generate DAST test script
/sast-full-scan my-repo --dast

# Run individual skills
/crawl dvja
/find-vulns-python --crawl crawl-output.json
/taint-trace --findings findings.json --crawl crawl-output.json
/validate-findings --findings findings.json
/scan-report --findings findings.json --ground-truth dvja-ground-truth.MD
/generate-fix FINDING-001
/scan-metrics --run-dir sast-runs/20260621-120000/
```
