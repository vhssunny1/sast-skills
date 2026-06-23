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
- `constants.py`, `defaults.py`, `secrets.py` — Python files with hardcoded fallback values
- `application.yml`, `application.properties` (Spring)
- `config/environments/*.rb` (Rails)
- `appsettings.json`, `appsettings.Production.json` (.NET)
- `config.json`, `config.example.json`, `config*.json`, `*.config.json` — JSON config files (websocket servers, queue workers, sidecars)

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
| `DEV_MODE=true`, `DEV_MODE=1` | App-specific dev mode — often disables auth enforcement or enables unsafe routes |
| `*_ENV=development`, `*_ENVIRONMENT=development`, `SUPERSET_ENV=development`, `NODE_ENV=development` in server-side services | Framework environment flag — enables dev behaviors even when `DEBUG` is separately false |
| `TESTING=true`, `TEST_MODE=1` | Test modes often disable security middleware |
| `*_ENABLED=true` where the var name contains `ADMIN`, `SUPERUSER`, `INTERNAL`, `UNSAFE` | Administrative/unsafe features enabled |

For each flagged env var, report a conditional finding: "This feature is enabled and exploitable only when this env var is set. Verify that the backend is not directly reachable when this flag is on."

### 2b — Weak or default secrets

Check these patterns:

| Pattern | Risk |
|---|---|
| Value contains `secret`, `changeme`, `change_me`, `change-me`, `password`, `example`, `test`, `sample`, `default`, `local`, `dev` | Placeholder value likely to be reused in production |
| Value is fewer than 32 characters | Too short for a cryptographic secret |
| Any variable whose name contains `SECRET`, `JWT`, `TOKEN_SECRET`, `API_KEY`, `COOKIE_SECRET`, `SESSION_SECRET` set to short or obviously placeholder values | Session forgery, JWT bypass — flag ALL matching vars, not just the primary SECRET_KEY. Applications often have secondary secrets (guest tokens, async-query tokens, websocket tokens) that are equally exploitable. |
| Same value used for multiple secrets (e.g. `SECRET_KEY` == `COOKIE_SECRET`) | Key reuse reduces isolation |

**Multi-secret scanning:** Many frameworks use multiple JWT secrets for different token types. Flag each one independently:
- Flask session: `SECRET_KEY`, `SUPERSET_SECRET_KEY`
- Guest/embed tokens: `GUEST_TOKEN_JWT_SECRET`, `*_GUEST_SECRET*`
- Async/queue tokens: `GLOBAL_ASYNC_QUERIES_JWT_SECRET`, `*_ASYNC_*SECRET*`
- Websocket/sidecar: look in JSON config files for `"jwtSecret"` fields

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

## Step 3b — Analyze constants.py / defaults.py / secrets.py

For Python files named `constants.py`, `defaults.py`, `secrets.py` at any depth:

Read the file. Look for string literals assigned to names that suggest secrets:
- Variable names containing `SECRET`, `KEY`, `JWT`, `PASSWORD`, `TOKEN`, `CREDENTIAL`
- Values matching: `CHANGE_ME*`, `*CHANGE_ME*`, `test-*`, `*-test`, `example`, `REPLACE_*`, `TODO_*`, any value surrounded by angle brackets like `<your-secret-here>`

These are **hardcoded fallback values** — the intent is for deployers to override them in `.env`, but if they don't, the application silently uses the insecure default. Flag each as a critical finding with severity based on the secret's purpose:
- Session/cookie key → critical (session forgery)
- JWT signing key → critical (auth bypass)
- Database password → high
- API key → medium

Example pattern to flag:
```python
CHANGE_ME_SECRET_KEY = "CHANGE_ME_TO_A_COMPLEX_RANDOM_SECRET"  # noqa: S105
CHANGE_ME_GUEST_TOKEN_JWT_SECRET = "test-guest-secret-change-me"  # noqa: S105
```

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

## Step 4b — Classify deployment context for each finding

Before scoring any config finding, determine the deployment intent of the file it came from. This prevents development templates from being reported at the same severity as production secrets.

### Signals to check (in order)

**1. Filename signals → `example_file`**

If the config filename (not path) contains any of: `example`, `sample`, `template`, `default`, `stub`, `proto`
→ classify as `example_file`

Examples: `config.example.json`, `.env.example`, `docker-compose.template.yml`

**2. Committed with warning comments → `development_template`**

Read the lines immediately before and after each flagged value. If any adjacent line (within 3 lines) contains phrases like:
- "change in production", "set this to a unique", "do not use in production"
- "replace before deploy", "override in production", "unique secure random"
- "Make sure you set", "TODO:", "FIXME:", "CHANGE_ME" (as a comment, not a value)

→ classify as `development_template`

**3. File is tracked in git but has warning comments elsewhere in the same file → `development_template`**

If the overall file contains a header or block comment warning that values must be replaced for production (e.g. a disclaimer at the top of a docker-compose file), classify all findings from that file as `development_template`.

**4. Hardcoded in application source code as a fallback → override to `source_code_fallback`**

If the finding's `file` is a Python/JS/TS source file (not a config file) — e.g. `constants.py`, `defaults.py` — and the value is a string literal assigned as a module-level constant, classify as `source_code_fallback`. This overrides any template signals: code-level fallbacks are unconditional and cannot be "overridden" at deploy time through documented convention.

**5. No template signals present → `production_config`**

If none of the above apply, classify as `production_config`.

### Store on the finding

Add `deployment_context` field to each config finding:
- `"example_file"` — explicitly a sample/template file
- `"development_template"` — committed dev config with documented warnings
- `"source_code_fallback"` — hardcoded in application source, unconditional
- `"production_config"` — no template signals, treat as real

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
  "condition": "REDASH_REMOTE_USER_LOGIN_ENABLED=true",
  "deployment_context": "production_config"
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
