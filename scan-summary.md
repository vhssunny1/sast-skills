# SAST Scan Report — Redash (Blind Scan)

**Repo:** c:/Users/Harikrishna_Valugond/SAST/redash  
**Scanned:** 2026-06-17  
**Languages:** Python (Flask) + TypeScript/React (polyglot)  
**Scan mode:** Blind — no prior CVE knowledge used. All findings derived from reading source code.

---

## Summary

| Metric | Value |
|---|---|
| Total findings | 6 |
| Critical | 0 |
| High | 3 |
| Medium | 2 |
| Low | 1 |
| Suppressed (likely FP) | 0 |
| Estimated precision | 83% |
| Recall (vs ground truth) | Not computed — no ground truth provided |
| Files with findings | 6 / 647 scanned |
| Positive signals found | 9 (DOMPurify, CSRF, LDAP escaping, etc.) |

---

## Confirmed & Likely Real Findings

---

### PY-001 — HIGH — CWE-94 — A03:2021

| Field | Value |
|---|---|
| File | `redash/query_runner/python.py` line 318 |
| Method | `run_query` |
| Status | confirmed |
| Confidence | 0.87 |

**What happens:**  
RestrictedPython's safety model relies on `_getattr_` being a guarded function that blocks access to double-underscore attributes (`__class__`, `__mro__`, `__subclasses__`). By assigning real Python `getattr` to `_getattr_`, this guard is removed. An attacker can write Python code that traverses the class hierarchy to locate `subprocess.Popen` or `os.system` and execute OS commands on the server. `setattr` is also exposed at line 319, enabling object mutation. Any authenticated user with execute access to a Python data source can escape the sandbox.

**Source:** `query` — user-submitted Python code via POST `/api/query_results`  
**Sink:** `exec(code, restricted_globals, self._script_locals)` at line 357

**Evidence:**
```python
builtins["_getattr_"] = getattr
```

**Taint path:**  
Step 1 — `redash/handlers/query_results.py` → `QueryResultListResource.post`: SOURCE — params['query'] from POST /api/query_results JSON body  
Step 2 — `redash/tasks/queries/execution.py` → `enqueue_query`: query_text passed to Celery worker  
Step 3 — `redash/query_runner/python.py` → `run_query`: SINK — compile_restricted(query) then exec() with _getattr_ = real getattr

**Fix:**  
```python
from RestrictedPython.Guards import safe_getattr
builtins['_getattr_'] = safe_getattr
```

---

### PY-002 — HIGH — CWE-78 — A03:2021

| Field | Value |
|---|---|
| File | `redash/query_runner/script.py` line 19 |
| Method | `run_script` |
| Status | confirmed |
| Confidence | 0.90 |

**What happens:**  
When the Script data source is configured with `path='*'`, `query_to_script_path()` returns the raw query string as the command. `subprocess.check_output(query, shell=True)` then executes any shell command the user provides. The class type is `insecure_script`, acknowledging the danger, but any user with access to this data source gains OS command execution with no per-query restriction.

**Source:** `query` — user-submitted command text via POST `/api/query_results`  
**Sink:** `subprocess.check_output(script, shell=shell)` where `script == query` when `path='*'`

**Evidence:**
```python
output = subprocess.check_output(script, shell=shell)
```

**Taint path:**  
Step 1 — `redash/handlers/query_results.py` → `QueryResultListResource.post`: SOURCE — params['query'] from POST body  
Step 2 — `redash/query_runner/script.py` → `run_query`: query_to_script_path(path='*', query) returns query unchanged  
Step 3 — `redash/query_runner/script.py` → `run_script`: SINK — subprocess.check_output(script=query, shell=True)

**Fix:**  
Remove `path='*'` support. Always enforce `shell=False` and resolve scripts against the configured path directory.

---

### PY-004 — HIGH — CWE-287 — A01:2021

| Field | Value |
|---|---|
| File | `redash/authentication/remote_user_auth.py` line 28 |
| Method | `login` |
| Status | confirmed |
| Confidence | 0.92 |
| Note | Feature disabled by default. Exploitable only when REMOTE_USER_LOGIN_ENABLED=true. |

**What happens:**  
When `REMOTE_USER_LOGIN_ENABLED=true`, any HTTP request to `/remote_user/login` with an `X-Forwarded-Remote-User` header creates and logs in a Redash user with that email — including admins — with no token or signature verification. Deployments with exposed backend ports allow full authentication bypass by setting this header.

**Source:** `request.headers.get(settings.REMOTE_USER_HEADER)` — `X-Forwarded-Remote-User`, attacker-controlled if backend directly reachable  
**Sink:** `create_and_login_user(current_org, email, email)` — Flask-Login session established

**Evidence:**
```python
email = request.headers.get(settings.REMOTE_USER_HEADER)
```

**Taint path:**  
Step 1 — `redash/authentication/remote_user_auth.py` → `login`: SOURCE — email from X-Forwarded-Remote-User header  
Step 2 — `redash/authentication/__init__.py` → `create_and_login_user`: SINK — user created/fetched, session established

**Fix:**  
Add HMAC signature verification between proxy and Redash, or replace with OAuth/SAML.

---

### TS-001 — MEDIUM — CWE-79 — A03:2021

| Field | Value |
|---|---|
| File | `viz-lib/src/visualizations/map/initMap.ts` line 147 |
| Method | `initMap (default popup branch)` |
| Status | confirmed |
| Confidence | 0.77 |

**What happens:**  
When a map visualization has no custom popup template, marker popups are built from a template literal that injects column values (`v`) from query results without sanitization. Leaflet's `bindPopup()` sets `innerHTML` internally. The custom-template branch (lines 134, 144) correctly wraps output in `sanitize()` — the default branch 12 lines below does not. If any data column contains HTML/script content, it executes when a user clicks a map marker.

**Source:** `v` — column values from query result rows  
**Sink:** `marker.bindPopup(template literal containing ${v})` — Leaflet sets `innerHTML`

**Evidence:**
```typescript
${map(row, (v, k) => `<li>${k}: ${v}</li>`).join("")}
```

**Taint path:**  
Step 1 — `viz-lib/src/visualizations/map/initMap.ts` → `initMap`: SOURCE — v = column value from query result row  
Step 2 — `viz-lib/src/visualizations/map/initMap.ts` → `initMap line 147`: SINK — marker.bindPopup(template literal with ${v})

**Fix:**  
`sanitize` is already imported on line 19. Wrap the default `bindPopup` call:
```typescript
marker.bindPopup(sanitize(`<ul>...<li>${k}: ${v}</li>...</ul>`));
```

---

### PY-003 — MEDIUM — CWE-918 — A10:2021 *(Likely Real)*

| Field | Value |
|---|---|
| File | `redash/query_runner/json_ds.py` line 197 |
| Method | `_get_all_results` |
| Status | likely_real |
| Confidence | 0.73 |
| Note | advocate protection ON by default; exploitable when REDASH_ENFORCE_PRIVATE_IP_BLOCK=false |

**What happens:**  
The JSON query runner fetches user-supplied URLs. SSRF protection depends entirely on `ENFORCE_PRIVATE_ADDRESS_BLOCK`: when `False`, plain `requests` is used with no SSRF protection. User-controlled `headers` and `auth` fields in the query body enable header injection alongside SSRF.

**Source:** `query['url']` — URL from user-supplied YAML query body  
**Sink:** `requests_session.request(method, url)` — advocate or plain requests

**Evidence:**
```python
results, error = self._get_all_results(query["url"], method, path, pagination, **request_options)
```

**Fix:**  
Make `advocate` non-optional. Remove the conditional import in `utils/requests_session.py`.

---

### TS-002 — LOW — CWE-346 — A07:2021 *(Likely Real)*

| Field | Value |
|---|---|
| File | `client/app/services/restoreSession.jsx` line 61 |
| Method | `showRestoreSessionPrompt (handlePostMessage)` |
| Status | likely_real |
| Confidence | 0.70 |

**What happens:**  
The session restore handler listens for `MessageEvent` from any origin without validating `event.origin`. An attacker with a window reference to Redash can send a spoofed message, causing the login modal to dismiss and the session-restore promise to resolve prematurely. Impact: UX disruption and repeated unauthenticated request retries.

**Source:** `event` — `MessageEvent` from any origin  
**Sink:** `closeModal()` + `onSuccess()` called without origin validation

**Evidence:**
```javascript
window.addEventListener("message", handlePostMessage, false);
```

**Fix:**  
```javascript
if (event.origin !== window.location.origin) return;
```

---

## Suppressed Findings

None.

---

## Precision / Recall

No ground truth provided (blind scan). All findings derived from code reading only.

**Estimated precision (score-based):** 83%

To compute against verified ground truth:
```
/scan-report --findings findings.json --ground-truth redash-ground-truth.MD
```

---

## Security Positive Signals

Controls found correctly implemented:

| Control | Location |
|---|---|
| `DOMPurify.sanitize()` applied to all `dangerouslySetInnerHTML` | `viz-lib/src/components/HtmlContent.tsx` |
| Markdown → HTML → DOMPurify pipeline | `TextboxWidget.jsx`, `VisualizationWidget.jsx` |
| CSRF token in axios (`xsrfCookieName: csrf_token`) | `client/app/services/axios.js` |
| Leaflet custom template popup/tooltip sanitized | `initMap.ts` lines 134, 144 |
| Open redirect stripped server-side (`get_next_path`) | `redash/authentication/__init__.py` |
| LDAP injection prevented (`escape_filter_chars`) | `redash/authentication/ldap_auth.py` |
| YAML parsed safely (`yaml.safe_load`) | `redash/query_runner/json_ds.py` |
| `postMessage` to parent uses `window.location.origin` | `restoreSession.jsx` line 10 |
| `eval()` absent from all client JS/TS | Full client codebase |

---

## Top 3 Fix Priorities

**Priority 1 — PY-001: RestrictedPython sandbox escape (one-line fix)**  
Replace real `getattr` with `safe_getattr` in `query_runner/python.py:318`. Eliminates sandbox escape for all Python query runner users.

**Priority 2 — PY-004: Remote user auth header trust**  
If `REMOTE_USER_LOGIN_ENABLED=true` in production: replace plain header trust with HMAC-signed assertions or migrate to OAuth/SAML.

**Priority 3 — TS-001: Leaflet map popup XSS**  
`sanitize` is already imported in the file. Wrap the default `bindPopup` with `sanitize()`. Three lines of change.

---

*Scan: 2026-06-17 | SAST-Agent v1.0.0 | Blind scan of Redash (28k GitHub stars, Python Flask + TypeScript React)*
