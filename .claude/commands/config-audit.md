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
- `*.cfg`, `*.conf`, `*.ini` — reverse proxy and sidecar config files (oauth2-proxy, nginx, gunicorn, uwsgi, supervisor)
- `Dockerfile`, `Dockerfile.*`, `*.dockerfile` — build-time supply chain
- `.gitlab-ci.yml`, `.github/workflows/*.yml`, `Jenkinsfile`, `*.pipeline.yml` — CI pipeline files
- `**/grafana/datasource*.yml`, `**/grafana/**/*.yml`, `**/dashboards/*.json` — Grafana datasource and dashboard configs
- `**/tempo/*.yml`, `**/tempo/**/*.yml` — Tempo (distributed tracing) configs
- `**/prometheus/*.yml`, `**/alertmanager/*.yml` — Prometheus and Alertmanager configs
- `**/pyproject.toml`, `**/setup.cfg`, `**/setup.py` — Python package manifests at any depth (nested packages, workspace members)
- `**/go.mod` — Go module manifests at any depth

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
| `OIDC_NONCE_ENABLED=false`, `OIDC_SKIP_NONCE=true`, `oidc_skip_nonce_enabled=true` | OIDC nonce validation disabled — allows token replay attacks with captured authorization codes (CWE-287) |
| `*MOCK_EMAIL*=<any value>`, `*_DEV_AUTH*=<any value>`, `*_FAKE_USER*=<any value>` | Developer mock authentication set — if there is no production guard in code, any user can authenticate as any email (CWE-290). Flag even when the variable is set to an empty string — presence alone enables the bypass path. |
| `CORS_ORIGIN=*` or `CORS_ORIGINS=*` **combined with** `CORS_ALLOW_CREDENTIALS=true` or `ACCESS_CONTROL_ALLOW_CREDENTIALS=true` | CORS wildcard + credentials: browser will send cookies to any cross-origin requester (CWE-942). The wildcard alone is medium risk; the combination is high because session cookies are exfiltrated. |

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

## Step 2d — Analyze `.cfg`, `.conf`, `.ini` files

These files use `key = value` or `key=value` format (INI-style), not shell variable export syntax. Apply the same checks as Step 2b/2c but match against lowercase key names.

**Secret variable names to flag (case-insensitive, INI key format):**
- `cookie_secret`, `cookie_secret_hmac`, `cookie_name`, `jwt_secret`, `session_secret`, `api_key`, `token_secret`, `signing_key`, `private_key`, `hmac_secret`

**oauth2-proxy.cfg specific patterns:**
```ini
cookie_secret = "short_or_placeholder"   # flag if value < 32 chars or matches placeholder patterns
provider = "github"                       # note auth provider for context
skip_auth_regex = ["/health"]             # if set to broader patterns, flag as auth bypass risk
email_domains = ["*"]                     # wildcard email domain — anyone with a valid OIDC token can authenticate
```

**For each key found:**
1. Apply the same placeholder/length checks as Step 2b: flag values < 32 chars, values containing `test`, `change`, `example`, `dev`, `secret` as substrings
2. `email_domains = ["*"]` — flag as medium risk: no domain restriction means any user authenticated via the OIDC provider can log in (CWE-284)
3. `skip_auth_regex` patterns broader than `/health` or `/metrics` — flag as auth bypass risk
4. Apply deployment context classification (Step 4b) the same as for .env files

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

### 3a (continued) — Datastore without authentication

For each service in the compose file whose image name contains `redis`, `postgres`, `mysql`, `mariadb`, `mongodb`, `mongo`, `memcached`, or `elasticsearch`:

Check whether the service has a password environment variable set:
- Redis: `REDIS_PASSWORD`, `requirepass`
- Postgres: `POSTGRES_PASSWORD`
- MySQL/MariaDB: `MYSQL_ROOT_PASSWORD`, `MYSQL_PASSWORD`
- MongoDB: `MONGO_INITDB_ROOT_PASSWORD`
- Elasticsearch: `ELASTIC_PASSWORD`, `xpack.security.enabled`

Flag as high severity (CWE-306) when:
- The service has a mapped host port (exposed to host network), AND
- No password environment variable is set in the `environment:` block

Flag as medium severity when the service has no exposed port but also has no password (reachable within the Docker network by all co-located services).

Example finding evidence: `redis: image: redis:7 — no REDIS_PASSWORD set, port 6379 exposed to host`
Fix hint: Add `command: redis-server --requirepass "${REDIS_PASSWORD}"` and set `REDIS_PASSWORD` in `.env`.

### 3b — Dangerous build/runtime flags

- `skip_frontend_build: "true"` (or similar) — acceptable if intentional, but note it
- `FLASK_ENV: development`, `NODE_ENV: development` in a service without `127.0.0.1` port restriction
- `privileged: true` — container runs with root capabilities on the host
- `network_mode: host` — bypasses Docker network isolation

### 3c — Supply chain risks in Dockerfiles

For each `Dockerfile` or `Dockerfile.*`, read it fully and check:

**Unpinned external code execution:**

| Pattern | Risk | Example |
|---|---|---|
| `RUN curl ... \| bash` or `RUN curl ... \| sh` without hash verification | Remote script executed at build time — if CDN/DNS is compromised, arbitrary code runs as root inside the image | `RUN curl -fsSL https://dot.net/v1/dotnet-install.sh \| bash` |
| `RUN wget ... -O- \| bash` | Same risk via wget | `RUN wget -qO- https://... \| bash` |
| `RUN git clone <url>` without subsequent `RUN git checkout <commit-sha>` | Any new commit pushed to the upstream branch is silently pulled into the next build — supply chain poisoning | `RUN git clone https://github.com/ggerganov/whisper.cpp` |
| `COPY *.whl .` or binary files committed to the repo and `pip install`ed | Binary wheel without source — cannot audit what the binary does | `COPY vendor/mylib-1.0-py3-none-any.whl .` |
| `RUN pip install git+https://github.com/org/repo` without `@<commit-sha>` | Mutable git reference — HEAD changes silently | `RUN pip install git+https://github.com/org/repo.git` |
| External binary downloaded with `curl -o binary` then `chmod +x binary && ./binary` without signature verification | Executable with no integrity check | `RUN curl -L https://releases.example.com/tool -o tool && chmod +x tool && ./tool` |
| `FROM <image>:latest` or `FROM <image>` without digest pin (`@sha256:...`) | Base image can change between builds silently | `FROM python:3.11` vs safe: `FROM python:3.11@sha256:abc123...` |
| `USER root` instruction (or absence of any `USER` instruction) in the final stage | Container runs as root inside the container — if the process is compromised, the attacker has root on the host if volumes are mounted or `privileged: true` is set | `USER root` or no `USER` in final `FROM` stage |

**USER root / missing USER check:**
Read each Dockerfile. If the final `FROM` stage contains no `USER` instruction (other than `USER root`), or explicitly sets `USER root`, flag as medium severity (CWE-250 — Execution with Unnecessary Privileges). Severity escalates to high if the compose file also sets `privileged: true` for this service.

Flag each as a supply chain finding with:
- `severity`: critical if the unverified code runs as root or at build time; high otherwise
- `cwe`: CWE-494 (Download of Code Without Integrity Check) or CWE-829 (Inclusion of Functionality from Untrusted Control Sphere)
- `deployment_context`: `production_config` (Dockerfiles are always build artifacts, not templates)

### 3d — CI pipeline injection

For each CI file (`.gitlab-ci.yml`, `.github/workflows/*.yml`, `Jenkinsfile`):

| Pattern | Risk |
|---|---|
| Unquoted variable in shell command: `- run: my-tool ${{ github.event.pull_request.title }}` | Attacker-controlled PR title injects shell commands into CI |
| GitLab CI unquoted variable: `- ${CI_COMMIT_BRANCH}` in a `script:` block without quoting | Branch name containing `;`, `&&`, or `\`cmd\`` executes arbitrary commands |
| `actions/checkout` with `ref: ${{ github.event.pull_request.head.ref }}` and subsequent `run:` using repo files | Malicious PR can inject code that runs in the CI context with repo secrets |
| Secrets printed in CI log: `echo $SECRET` or `run: echo "Token: $TOKEN"` | Secret exposed in CI log output |
| Unquoted `$VARIABLE` in GitHub Actions `run:` block: `run: ./deploy.sh $BRANCH_NAME` where `BRANCH_NAME` comes from `github.head_ref` or similar | Branch name with shell metacharacters executes arbitrary commands in the CI runner | CWE-78 |
| Unquoted `$CI_*` variable in GitLab CI `script:` block: `- ./build.sh $CI_COMMIT_REF_NAME` | Same risk — GitLab CI variables expanded by shell | CWE-78 |
| GitHub Actions `env:` block setting a variable from a github context value without quoting in subsequent `run:`: `env: TITLE: ${{ github.event.issue.title }}` then `run: echo $TITLE` | Issue title set as env var then used unquoted — shell expansion | CWE-78 |

**Unquoted variable rule:** Any `$VARIABLE` or `${VARIABLE}` that (a) derives from attacker-controlled input (PR title, branch name, issue body, commit message, tag name) and (b) appears unquoted in a shell `run:` or `script:` block is a CI injection vector. The existing `${{ github.* }}` check covers direct GitHub context interpolation; this check covers indirect injection through env vars set from those contexts.

Flag CI injection as CWE-78 (command injection) at high severity.

### 3e — Secrets in compose file (not in .env)

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
  "deployment_context": "production_config",
  "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
  "cvss_score": 9.1
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
| Download without integrity check (supply chain) | CWE-494 | A08:2021 |
| Untrusted code inclusion (supply chain) | CWE-829 | A08:2021 |
| CI pipeline command injection | CWE-78 | A03:2021 |
| OIDC nonce disabled / token replay | CWE-287 | A07:2021 |
| CORS wildcard + credentials | CWE-942 | A05:2021 |
| Mock auth bypass without production guard | CWE-290 | A07:2021 |
| Overly permissive email domain / auth scope | CWE-284 | A01:2021 |

**CVSS 3.1 scoring** — For every config finding, assign `cvss_vector` and `cvss_score`. Config findings have no attacker-controlled taint flow, so score based on what an attacker can do once they exploit the misconfiguration:

| Config class | Typical vector | Score |
|---|---|---|
| Auth bypass feature enabled (e.g. REMOTE_USER) | CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N | 9.1 |
| Hardcoded secret — network exploitable (JWT, session key) | CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N | 9.1 |
| Hardcoded secret committed to source | CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N | 7.7 |
| CI pipeline curl\|sh (no hash check) | CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H | 9.0 |
| Unpinned Docker/action tag (mutable) | CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H | 8.1 |
| Backend port exposed, proxy bypassed | CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N | 9.1 |
| Debug mode enabled | CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N | 5.3 |
| CORS wildcard + credentials | CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N | 6.5 |
| CSRF disabled | CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N | 6.5 |
| OIDC nonce validation disabled (token replay) | CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N | 8.1 |
| Safety/dev mode flag — deployment_template context | CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:L/I:L/A:N | 3.3 |
| Version number exposed | CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N | 5.3 |

Adjust for `deployment_context`: `development_template` or `example_file` findings where the risk is conditional should use AC:H and possibly AV:L to reflect that exploitation requires the insecure default to survive to production.

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
  Dockerfiles read : <N>
  CI files read    : <N>
  Findings         : <total> (<critical> critical / <high> high / <medium> medium / <low> low)
  Dangerous flags  : <list of enabled feature flags>
  Weak secrets     : <N> secret vars flagged
  Port exposure    : <N> backend ports exposed
  Supply chain     : <N> unpinned/unverified build-time dependencies
  CI injection     : <N> unquoted variables in CI scripts
  Output           : findings.json (appended)
```
