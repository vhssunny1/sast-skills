Audit configuration files for dangerous defaults, feature flags enabled in dangerous modes, and weak secrets. Produces findings without reading any application source code.

This skill runs AFTER crawl and BEFORE find-vulns. It focuses exclusively on deployment configuration — not application logic.

## Input

`$ARGUMENTS` format: `<repo-path>`

- `<repo-path>` — path to the repository root

---

## What this skill checks

Configuration bugs are often the most exploitable: a single env var can expose an authentication bypass, a docker-compose port mapping can make a private backend publicly reachable, and a default secret key can allow session forgery.

---

## Step 1 — Find config files

Walk `<repo-path>`. Collect these files:

- `.env`, `.env.local`, `.env.production`, `.env.development`, `*.env`
- `docker-compose.yml`, `docker-compose.yaml`, `compose.yaml`, `compose.yml`
- `settings.py`, `settings/*.py`, `config.py`, `config/*.py`
- `application.yml`, `application.properties` (Spring)
- `config/environments/*.rb` (Rails)
- `appsettings.json`, `appsettings.Production.json` (.NET)

If none found, note it in warnings and stop.

---

## Step 2 — Analyze .env and environment files

For each .env file, read it fully and check:

### 2a — Feature flags enabled in dangerous modes

Look for env vars that gate security-sensitive features. Flag any that are enabled (`=true`, `=1`, `=yes`, `=enabled`):

| Pattern | Risk |
|---|---|
| `*_LOGIN_ENABLED=true`, `*_AUTH_BYPASS*=true`, `REMOTE_USER*=true` | Authentication bypass features enabled — verify network isolation |
| `DEBUG=true`, `FLASK_DEBUG=1`, `DJANGO_DEBUG=True`, `RAILS_ENV=development` | Debug mode exposes stack traces, may disable auth checks |
| `TESTING=true`, `TEST_MODE=1` | Test modes often disable security middleware |
| `*_ENABLED=true` where the var name contains `ADMIN`, `SUPERUSER`, `INTERNAL`, `UNSAFE` | Administrative/unsafe features enabled |

For each flagged env var, report a conditional finding: "This feature is enabled and exploitable only when this env var is set. Verify that the backend is not directly reachable when this flag is on."

### 2b — Weak or default secrets

Check these patterns:

| Pattern | Risk |
|---|---|
| Value contains `secret`, `changeme`, `password`, `example`, `test`, `sample`, `default`, `local`, `dev` | Placeholder value likely to be reused in production |
| Value is fewer than 32 characters | Too short for a cryptographic secret |
| `SECRET_KEY`, `COOKIE_SECRET`, `JWT_SECRET`, `SESSION_SECRET`, `API_KEY` set to short or obvious values | Session forgery, JWT bypass |
| Same value used for multiple secrets (e.g. `SECRET_KEY` == `COOKIE_SECRET`) | Key reuse reduces isolation |

### 2c — Dangerous boolean defaults

- `SSL_VERIFY=false`, `TLS_VERIFY=false`, `VERIFY_CERTIFICATES=false` → MITM risk
- `SECURE_COOKIES=false`, `SESSION_COOKIE_SECURE=false` → session theft over HTTP
- `CSRF_ENABLED=false`, `WTF_CSRF_ENABLED=false` → CSRF protection disabled
- `CORS_ORIGINS=*`, `ACCESS_CONTROL_ALLOW_ORIGIN=*` → broad CORS

---

## Step 3 — Analyze docker-compose files

For each compose file, read it fully and check:

### 3a — Backend port exposure

Flag any service that maps a backend port to the host with `0.0.0.0` binding or no IP restriction:

```yaml
ports:
  - "5000:5000"        # flags: backend exposed on all interfaces
  - "0.0.0.0:5000:5000"  # explicit 0.0.0.0 — same risk
  - "127.0.0.1:5000:5000"  # safe: loopback only
```

If a reverse proxy service (nginx, caddy, traefik) is present in the same compose file AND the backend also has a mapped port, flag the backend port as "proxy bypass risk" — an attacker with host access can reach the backend directly, bypassing the proxy's auth/TLS.

### 3b — Dangerous build/runtime flags

- `skip_frontend_build: "true"` (or similar) — acceptable if intentional, but note it
- `FLASK_ENV: development`, `NODE_ENV: development` in a service without `127.0.0.1` port restriction
- `privileged: true` — container runs with root capabilities on the host
- `network_mode: host` — bypasses Docker network isolation

### 3c — Secrets in compose file (not in .env)

If `environment:` block hard-codes values like `SECRET_KEY: mysecret` instead of `${SECRET_KEY}`, flag as secret in version-controlled file.

---

## Step 4 — Analyze settings.py / application.properties

For Python `settings.py` or `config.py`:
- `DEBUG = True` → stack traces, Werkzeug debugger PIN (RCE in dev)
- `ALLOWED_HOSTS = ["*"]` → Host header injection
- `SECRET_KEY` set to a string literal shorter than 32 chars
- Any `os.environ.get("KEY", "default_value")` where `default_value` is non-empty and looks like a credential

For Spring `application.yml`:
- `management.endpoints.web.exposure.include: "*"` → Actuator exposes all endpoints including `/env`, `/heapdump`
- `spring.security.enabled: false`
- `server.ssl.enabled: false`

---

## Step 5 — Write findings

Append to `findings.json` (create if not exists). Use the same schema as find-vulns but with `source: "configuration"`:

```json
{
  "id": "CONFIG-001",
  "cwe": "CWE-16",
  "owasp": "A05:2021",
  "severity": "high",
  "confidence": 0.95,
  "confidence_note": "",
  "file": ".env",
  "line": 4,
  "method": "environment",
  "source": "REDASH_REMOTE_USER_LOGIN_ENABLED env var",
  "sink": "remote_user_auth.py — login() endpoint trusts X-Forwarded-Remote-User header without signature verification",
  "sanitization_present": "none — feature is active unconditionally when this var is true",
  "evidence": "REDASH_REMOTE_USER_LOGIN_ENABLED=true",
  "description": "Remote user authentication is enabled. When the backend port is directly reachable (common in Docker deployments), any attacker can authenticate as any user by forging the X-Forwarded-Remote-User header.",
  "fix_hint": "Set REDASH_REMOTE_USER_LOGIN_ENABLED=false unless SSO proxy is deployed, or add HMAC signature verification to the remote_user_auth.py login endpoint.",
  "condition": "REDASH_REMOTE_USER_LOGIN_ENABLED=true"
}
```

**CWE mapping for config findings:**

| Class | CWE | OWASP |
|---|---|---|
| Security feature disabled | CWE-16 | A05:2021 |
| Default credentials / weak secret | CWE-521 | A02:2021 |
| Debug mode in production | CWE-94 | A05:2021 |
| Backend port exposed bypassing proxy | CWE-284 | A01:2021 |
| CSRF protection disabled | CWE-352 | A01:2021 |
| Insecure TLS configuration | CWE-295 | A02:2021 |

---

## Hard rules

- Do NOT read application source code. Only read configuration files.
- `evidence` must be the verbatim line from the config file.
- Do not speculate about vulnerabilities that require source code knowledge — flag the config risk only and note which source file to check.
- `condition` field is always set (either the env var name/value, or `null` for unconditional settings).

---

## Completion

```
config-audit complete.
  Repo             : <repo-path>
  Config files read: <N>
  Findings         : <total> (<critical> critical / <high> high / <medium> medium / <low> low)
  Dangerous flags  : <list of enabled feature flags>
  Weak secrets     : <N> secret vars flagged
  Port exposure    : <N> backend ports exposed
  Output           : findings.json (appended)
```
