Scan a Java repository for security vulnerabilities by reasoning about data flow — sources, paths, sinks, and sanitization gaps. Write structured findings to findings.json.

Do NOT pattern-match against a checklist of known bugs. Reason from first principles: what data enters each method, where does it go, and what could an attacker do if they controlled it?

## Input

`$ARGUMENTS` format: `[--crawl <path>]`

- `--crawl <path>` — path to `crawl-output.json` (default: `./crawl-output.json`)

---

## Step 1 — Load crawl manifest

Read `crawl-output.json`. Extract `repo_path`, `files[]`, `framework`. If missing, print an error and stop.

---

## Step 2 — Build the scan queue

Analyze files in this priority order:

1. `entry_point` Java files
2. `dao` Java files
3. `service` Java files
4. `filter_interceptor`, `config`, `util` Java files
5. JSP/JSPX files — glob `<repo_path>/src/main/webapp/**/*.jsp`
6. XML config files — `struts.xml`, `web.xml`, `applicationContext.xml`, `persistence.xml`

---

## Step 3 — Sources, sinks, and sanitization

### Sources (attacker-controlled data)

- **Struts2 action fields with setters** — any field with a `setXxx()` method. Struts2 auto-populates these from HTTP request parameters. This is the primary injection vector for Struts apps.
- **Spring `@RequestParam`, `@PathVariable`, `@RequestBody`, `@RequestHeader`** — method parameters annotated with these are user-controlled
- **Explicit request access** — `request.getParameter()`, `request.getHeader()`, `request.getQueryString()`, `request.getCookies()`
- **Session attributes** — only when traceable to user input origin
- **Database values that were user-supplied** — product names, bios, tags, any free-text field a user wrote

Taint propagates through: method arguments, return values, field assignment, string concatenation, and collection reads.

### Sinks (dangerous operations)

| Sink | Examples | Risk |
|---|---|---|
| SQL/query execution | `createQuery()`, `createNativeQuery()`, `prepareStatement()`, `executeQuery()`, HQL/JPQL string concat | SQL/JPQL injection |
| Shell execution | `Runtime.exec()`, `ProcessBuilder`, `exec(new String[]{...})` | Remote code execution |
| HTML/JS output | `response.getWriter().write()`, JSP `<%= %>`, `out.print()`, `<s:property escape="false">` | XSS |
| Redirect | `response.sendRedirect(userValue)`, Struts2 redirect with user-controlled result | Open redirect |
| Auth decision | Branch on `cookie.getValue()`, `request.getHeader()` to grant/deny admin access | Privilege escalation |
| Deserialization | `ObjectInputStream.readObject()`, `fromJson()` on untrusted input | Remote code execution |
| Crypto on password | MD5/SHA1 for password hashing, `MessageDigest.getInstance("MD5")` | Weak credential storage |
| Log output | `logger.info(password)`, `log.debug(token)` | Sensitive data in logs |

### Sanitization that breaks the chain

- **Parameterized queries** — `setParameter("name", value)`, `?` placeholders with `PreparedStatement` — breaks SQL injection
- **Allowlist validation with rejection** — `if (!value.matches("[a-zA-Z0-9]+")) throw/return` — breaks injection
- **Output encoding** — `fn:escapeXml()`, `<c:out value="..."/>` — breaks XSS
- **URL allowlist for redirects** — validates against fixed domain list — breaks open redirect
- **Server-side session check** — `session.getAttribute("user")` for identity (not cookie value) — breaks auth bypass
- **bcrypt, argon2, PBKDF2** — breaks weak crypto finding

Not sanitization: null checks, length checks, logging the value, casting to int (unless numeric injection is the concern).

---

## Step 4 — Analyze each Java file

For every file in the scan queue, read the full file, then for each method ask:

**Q1 — Taint:** What enters this method? What sinks are in the body? Does any tainted value reach a sink without effective sanitization?

**Q2 — Authorization:** Does this method perform a privileged operation? Is the authorization check based on session state (secure) or a client-supplied header/cookie (insecure)?

**Q3 — Crypto:** Does this method hash or compare passwords/tokens? Is the algorithm modern (bcrypt, argon2, PBKDF2)? Is a random salt used?

**Q4 — Sensitive data in logs:** Does this method log passwords, tokens, or keys?

**Q5 — Null safety:** Does a user-triggered lookup return null that is used without a null check?

---

## Step 5 — Analyze JSP/JSPX files

For each JSP, ask:

**Q1 — Output encoding:** Is every value from request/session/action getter HTML-encoded before writing to the response?
- Dangerous: `<%= expr %>`, `${param.x}` without `fn:escapeXml()`, `<s:property escape="false">`
- Safe: `<c:out value="${x}"/>`, `${fn:escapeXml(x)}`, `<s:property>` default

**Q2 — Direct parameter output:** Is `request.getParameter()` written directly to the page without encoding? That is always reflected XSS.

---

## Step 6 — Analyze XML config files

Read `struts.xml`, `web.xml`, `applicationContext.xml`. Look for:
- Struts devMode enabled (`<constant name="struts.devMode" value="true"/>`)
- Verbose error pages / stack traces exposed to users
- Default credentials in datasource config
- Overly permissive CORS or CSP

---

## Step 7 — Score, deduplicate, assign IDs

**Confidence:**
- 0.90–1.00 — source and sink in same method, direct taint, no sanitization visible
- 0.70–0.89 — one hop of reasoning required (framework populates field, used at sink)
- 0.50–0.69 — indirect path, cross-method, sanitization may exist elsewhere
- < 0.50 — discard

**Filter:** ≥ 0.70 report; 0.50–0.69 report with `confidence_note: "indirect path — verify manually"`.

**Deduplicate:** same CWE + same file + same line ±3 → keep higher confidence.

**Number:** `FINDING-001`, `FINDING-002`, ...

**CWE/OWASP mapping:**

| Class | CWE | OWASP |
|---|---|---|
| SQL/query injection | CWE-89 | A03:2021 |
| Command injection | CWE-78 | A03:2021 |
| XSS | CWE-79 | A03:2021 |
| SSRF | CWE-918 | A10:2021 |
| Unvalidated redirect | CWE-601 | A01:2021 |
| Insecure auth (client-controlled) | CWE-285 | A01:2021 |
| IDOR / missing ownership check | CWE-639 | A01:2021 |
| Weak password hash | CWE-916 | A02:2021 |
| Sensitive data in logs | CWE-532 | A09:2021 |
| Dev/debug mode exposed | CWE-209 | A05:2021 |
| Insecure deserialization | CWE-502 | A08:2021 |
| Missing auth for critical function | CWE-306 | A07:2021 |

---

## Step 8 — Write findings.json

Write to `findings.json` in the current working directory. Overwrite if exists.

```json
{
  "scanned_at": "<ISO 8601>",
  "repo_path": "<absolute path>",
  "language": "java",
  "crawl_input": "./crawl-output.json",
  "total_findings": 0,
  "findings_by_severity": { "critical": 0, "high": 0, "medium": 0, "low": 0 },
  "findings": [
    {
      "id": "FINDING-001",
      "cwe": "CWE-89",
      "owasp": "A03:2021",
      "severity": "critical",
      "confidence": 0.95,
      "confidence_note": "",
      "file": "src/main/java/com/example/UserService.java",
      "line": 75,
      "method": "findByLogin",
      "source": "login — @RequestParam, caller passes HTTP query param",
      "sink": "entityManager.createQuery() — JPQL built by string concatenation",
      "sanitization_present": "none",
      "evidence": "entityManager.createQuery(\"SELECT u FROM User u WHERE u.login = '\" + login + \"'\")",
      "description": "The login parameter is concatenated directly into a JPQL query string. An attacker can inject JPQL syntax to bypass authentication or enumerate users.",
      "fix_hint": "Use a named parameter: createQuery(\"SELECT u FROM User u WHERE u.login = :login\").setParameter(\"login\", login)"
    }
  ],
  "skipped_files": [],
  "warnings": []
}
```

---

## Hard rules

- Report only what you can see in the code you read. Do not invent findings.
- `evidence` must be the verbatim line from the file (leading whitespace trimmed only).
- `source` must name the specific variable or call that introduces user-controlled data.
- `sink` must name the specific dangerous operation.
- Do not consult ground truth files, CVE lists, or prior knowledge of this codebase. Findings must come from reading the code.

---

## Completion

```
find-vulns-java complete.
  Repo          : <repo_path>
  Files scanned : <N> Java + <N> JSP + <N> XML
  Findings      : <total> (<critical> critical / <high> high / <medium> medium / <low> low)
  Output        : findings.json
```
