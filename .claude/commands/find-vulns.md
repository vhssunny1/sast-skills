Scan a Java repository for security vulnerabilities by reasoning about data flow — sources, paths, sinks, and sanitization gaps. Write structured findings to findings.json.

Do NOT pattern-match against a checklist of known bugs. Reason from first principles: what data enters each method, where does it go, and what could an attacker do if they controlled it?

## Input

`$ARGUMENTS` format: `[--crawl <path>] [--repo <path>]`

- `--crawl <path>` — path to `crawl-output.json` (default: `./crawl-output.json`)
- `--repo <path>` — repo root override (default: read `repo_path` from crawl-output.json)

If no arguments, use `./crawl-output.json` and `repo_path` from inside it.

## Step 1 — Load crawl manifest

Read `crawl-output.json`. Extract:
- `repo_path` — absolute path to repo root
- `files[]` — all classified Java files (`path`, `role`, `lines`)
- `framework` — informs how user input enters the app

If `crawl-output.json` is missing or unparseable, print an error and stop.

## Step 2 — Build the scan queue

Analyze files in this priority order (higher attack surface first):

1. Java files with role `entry_point`
2. Java files with role `dao`
3. Java files with role `service`
4. Java files with role `filter_interceptor`, `config`, `util`
5. JSP/JSPX files — glob `<repo_path>/src/main/webapp/**/*.jsp` directly (not in crawl-output.json)
6. XML config files — `struts.xml`, `web.xml`, `applicationContext.xml`, `persistence.xml`

Skip any file in `crawl-output.json` `skipped_files[]`. Skip any file over 5000 lines (add to output `skipped_files`).

## Step 3 — Understand the threat model before you read any file

Before analyzing any file, internalize these concepts. Apply them throughout the scan.

### What counts as a SOURCE (attacker-controlled data)

A value is tainted (attacker-controlled) if it originates from:

- **Struts2/MVC action fields with setters** — any field that has a `setXxx()` method. In Struts2, the framework automatically populates these from HTTP request parameters. This is the primary injection vector.
- **Explicit request access** — `request.getParameter()`, `request.getHeader()`, `request.getQueryString()`, `request.getCookies()`
- **Session attributes set from request data** — only when you can trace that the session value was originally placed there from user input
- **Database values that were originally user-supplied** — product names, user bios, tags — any field a user could have written

Taint propagates: if a tainted value is passed to a method, stored in a field, or concatenated into a string, the result is also tainted.

### What counts as a SINK (dangerous operation)

A sink is dangerous if an attacker controlling its input can cause harm:

| Sink Category | Examples | Harm if attacker controls input |
|---|---|---|
| Query execution | `createQuery()`, `createNativeQuery()`, `prepareStatement()`, `executeQuery()`, HQL/JPQL string builders | Data exfiltration, auth bypass, data corruption |
| Shell execution | `Runtime.exec()`, `ProcessBuilder`, any OS command | Arbitrary code execution on server |
| HTML/JS output | `response.getWriter().write()`, JSP `<%= %>`, `out.print()`, Struts2 `<s:property>` | XSS — attacker runs JS in victim's browser |
| Redirect/forward | `response.sendRedirect()`, Struts2 redirect result with user-controlled URL field | Open redirect, phishing |
| Authorization decision | Branch on client-supplied value (`cookie.getValue()`, `request.getHeader()`) to determine if user is admin/authorized | Privilege escalation |
| Cryptographic operation on passwords/tokens | Hashing, encrypting, or comparing password/token values | Credential compromise if algorithm is weak or key is predictable |
| Log output | `logger.info/debug/warn/error()` | Sensitive data exposure in log files |
| Object deserialization | `ObjectInputStream.readObject()`, `fromJson()` on untrusted input | Remote code execution |

### What counts as SANITIZATION (breaks the path)

A sanitization breaks the taint path between a source and a sink IF it genuinely removes or neutralizes the attacker's control:

- **Parameterized queries / prepared statements** — `setParameter("name", value)` — sanitizes query sinks
- **Input validation with allowlist** — regex that permits only safe characters (e.g. `[a-zA-Z0-9.]` for IP), AND the code rejects or terminates on mismatch — sanitizes injection sinks
- **Output encoding** — `fn:escapeXml()`, `<c:out value="..."/>`, HTML-encoding before writing to response — sanitizes XSS sinks
- **URL allowlist check** — validating redirect URL against a fixed list of permitted domains — sanitizes redirect sinks
- **Server-side session check** — verifying identity from session (not from cookie value) before privileged operation — sanitizes auth sinks
- **Ownership check** — verifying `resource.getOwnerId() == sessionUser.getId()` before operating on a resource — sanitizes IDOR sinks
- **Modern password hashing** — bcrypt, argon2, PBKDF2 with salt — sanitizes crypto sinks
- **Null check** — `if (result != null)` before calling methods on a result that could be null

**Key judgment:** An input-length check, a null check, or a log statement around the sink does NOT sanitize it unless it actually prevents the attacker from controlling the dangerous value.

## Step 4 — Analyze each Java file

For every Java file in the scan queue:

**4a. Read the full file.**

**4b. For each method in the file, ask these questions:**

**Question 1 — Injection / taint analysis:**
> List every input to this method (parameters, fields populated by framework, request data). For each dangerous sink in this method body, trace whether any input reaches it. If a tainted value reaches a sink without effective sanitization between them, report a finding.

**Question 2 — Authorization analysis:**
> Does this method perform a privileged operation (modifying data, accessing other users' data, admin function)? If yes — is there a server-side check that verifies the caller has permission? Is that check based on session state (secure) or on a client-supplied value like a cookie (insecure)?

**Question 3 — Cryptographic analysis:**
> Does this method hash, encrypt, or compare passwords or security tokens? If yes — is the algorithm modern and resistant to brute force (bcrypt, argon2, PBKDF2)? Is a random salt used? Or is a weak/predictable algorithm used (MD5, SHA1, unsalted)?

**Question 4 — Sensitive data exposure:**
> Does this method write to a log? If yes — does the log statement include passwords, tokens, keys, or other values that should not appear in log files?

**Question 5 — Error and null safety:**
> Does this method call a function that can return null (a lookup, a find, a query)? If yes — is the result null-checked before its methods are called? An unguarded null dereference on a user-triggered lookup can be used for DoS.

For each finding you identify, record: the method name, the line where the sink is, the source of the tainted value, and what sanitization (if any) is present and why it is insufficient.

## Step 5 — Analyze each JSP/JSPX file

For every JSP file:

**5a. Read the full file.**

**5b. Ask these questions:**

**Question 1 — Output encoding:**
> Find every place where a value from the request, a session attribute, or an action's getter is written into the HTML response. Is that value HTML-encoded before output? Encoding must happen at the point of output — encoding elsewhere does not count.
>
> Dangerous: `<%= expr %>`, `out.print(expr)`, `${param.x}` without `fn:escapeXml()`, `<s:property>` with `escape="false"`
>
> Safe: `<c:out value="${x}"/>`, `${fn:escapeXml(x)}`, `<s:property>` with default (`escape="true"`)

**Question 2 — Direct request parameter output:**
> Is `request.getParameter()` used anywhere in this JSP, and is its output written directly to the page without encoding? This is always reflected XSS.

## Step 6 — Analyze XML config files

For every config XML file:

**6a. Read the file.**

**6b. Ask:**
> Are there configuration flags that are safe for development but dangerous in production?
> - Debug/dev mode enabled (Struts devMode, servlet debug, verbose error pages)
> - Stack traces shown to users
> - Default credentials
> - Overly permissive CORS or CSP

Report any dangerous configuration as a finding.

## Step 7 — Score, filter, and assign IDs

For each candidate finding:

**Assign confidence** based on how directly you can see the source-to-sink path:
- **0.90–1.00** — Source and sink are in the same method; taint is direct; no sanitization visible anywhere in the method
- **0.70–0.89** — Source enters via a parameter; taint is likely but requires one hop of reasoning (e.g. field set by framework, then used in a sink two lines later)
- **0.50–0.69** — Taint path exists but is indirect or requires reasoning across multiple methods; sanitization may exist elsewhere
- **< 0.50** — Too speculative; you cannot clearly show the source→sink path in the code you read

**Filter:**
- ≥ 0.70 → report as finding
- 0.50–0.69 → report with `"confidence_note": "indirect path — verify manually"`
- < 0.50 → discard

**Number sequentially:** `FINDING-001`, `FINDING-002`, ...

**Assign CWE and OWASP** based on the vulnerability class you identified:

| Class | CWE | OWASP 2021 |
|---|---|---|
| SQL / query injection | CWE-89 | A03 |
| Command injection | CWE-78 | A03 |
| XSS | CWE-79 | A03 |
| Unvalidated redirect | CWE-601 | A01 |
| Insecure auth decision (client-controlled) | CWE-285 | A01 |
| IDOR / missing ownership check | CWE-639 | A01 |
| Weak password hash | CWE-916 | A02 |
| Predictable security token | CWE-340 | A07 |
| Sensitive data in logs | CWE-532 | A09 |
| Dev/debug mode exposed | CWE-209 | A05 |
| Null dereference on user-controlled lookup | CWE-476 | A05 |
| Insecure deserialization | CWE-502 | A08 |

## Step 8 — Deduplicate

If two findings identify the same vulnerability class in the same file at the same line (±3 lines), keep only the higher-confidence one.

## Step 9 — Write findings.json

Write to `findings.json` in the current working directory. Overwrite if exists.

## Output Schema

```json
{
  "scanned_at": "<ISO 8601 timestamp>",
  "repo_path": "<absolute path>",
  "crawl_input": "<path to crawl-output.json>",
  "total_findings": 0,
  "findings_by_severity": {
    "critical": 0,
    "high": 0,
    "medium": 0,
    "low": 0
  },
  "findings": [
    {
      "id": "FINDING-001",
      "cwe": "CWE-89",
      "owasp": "A03:2021",
      "severity": "critical | high | medium | low",
      "confidence": 0.95,
      "confidence_note": "",
      "file": "src/main/java/com/example/UserService.java",
      "line": 75,
      "method": "findByLoginUnsafe",
      "source": "login — method parameter, caller passes HTTP request field",
      "sink": "entityManager.createQuery() — query string built by string concatenation",
      "sanitization_present": "none",
      "evidence": "Query query = entityManager.createQuery(\"SELECT u FROM User u WHERE u.login = '\" + login + \"'\");",
      "description": "The login parameter is concatenated directly into a JPQL query string. An attacker can inject JPQL syntax to bypass authentication or enumerate users.",
      "fix_hint": "Use a named parameter: createQuery(\"SELECT u FROM User u WHERE u.login = :login\").setParameter(\"login\", login)"
    }
  ],
  "skipped_files": [
    { "path": "...", "reason": "exceeds line limit | unreadable" }
  ],
  "warnings": []
}
```

## Severity guidelines

| Severity | Criteria |
|---|---|
| Critical | Direct attacker control of server execution, authentication bypass, or full data exfiltration |
| High | Significant data exposure, privilege escalation, or persistent XSS |
| Medium | Reflected XSS, open redirect, sensitive data in logs, weak crypto, dev mode |
| Low | Defense-in-depth issues, potential null dereference with limited exploitability |

## Hard rules

- Report only what you can see in the code you read. Do not invent findings.
- `evidence` must be the verbatim line from the file (trimmed of leading whitespace only).
- `source` must name the specific variable or call that introduces user-controlled data.
- `sink` must name the specific operation that is dangerous.
- `sanitization_present` must describe any validation/encoding you observed, even if insufficient — or "none".
- JSP files are not in crawl-output.json. Glob for them: `<repo_path>/src/main/webapp/**/*.jsp`
- Do not reference ground truth, known CVEs, or prior knowledge of this specific codebase to generate findings. Find them in the code.

## Downstream consumers

- `/validate-findings` reads `findings.json` to score false positive likelihood
- `/taint-trace` reads `findings.json` to trace cross-file data flows for high-confidence findings
- `/scan-report` reads `findings.json` to produce SARIF + markdown summary

## Completion

```
find-vulns complete.
  Repo          : <repo_path>
  Files scanned : <N> Java + <N> JSP + <N> XML
  Findings      : <total> (<critical> critical / <high> high / <medium> medium / <low> low)
  Output        : findings.json
```
