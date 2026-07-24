Scan a Java repository for security vulnerabilities by reasoning about data flow — sources, paths, sinks, and sanitization gaps. Write structured findings to findings.json.

Do NOT pattern-match against a checklist of known bugs. Reason from first principles: what data enters each method, where does it go, and what could an attacker do if they controlled it?

## Input

`$ARGUMENTS` format: `[--crawl <path>]`

- `--crawl <path>` — path to `crawl-output.json` (default: `./crawl-output.json`)

---

## Step 1 — Load crawl manifest

Read `crawl-output.json`. Extract `repo_path`, `files[]`, `framework`. If missing, print an error and stop.

---

## Step 1.5 — Load CPG taint hints (if available)

Check if `cpg-output.json` exists in the current directory.

**If absent or `"available": false`:** skip silently. Proceed with standard LLM discovery.

**If `"available": true`:** load the CPG and apply. Check for `"degraded": true` first — if present, `taint_paths[]`/`unreachable_sinks[]` are always empty (a known upstream Joern limitation — see `harness/scripts/joern_extract.sc`'s header comment). In that case `sinks_found[]` is the populated signal; the steps below use whichever arrays are non-empty without special branching.

### 1.5a — Boost file priorities by CPG hit count

Build a per-file hit count from **both** `taint_paths[]` (source_file/sink_file, if non-empty) and `sinks_found[]` (file, if non-empty — a sink location with no traced source, still real CPG signal). Boost `security_priority` in the crawl manifest:
- ≥ 5 combined hits → max(existing, 5)
- 2–4 combined hits → max(existing, 4)
- 1 combined hit → max(existing, 3)

### 1.5b — Load call graph

Store `call_graph[]` as `CPG_CALL_GRAPH` (callee_file + callee_method → callers list).
During Step 3 analysis, check `CPG_CALL_GRAPH` to resolve callers without reading additional files.
This is especially valuable for Java where Struts2/Spring autowiring makes caller discovery hard.

### 1.5c — Pre-populate CPG candidates

For each entry in `taint_paths[]` (full traced flow): create a pre-candidate with `cpg_guided: true, cpg_source_confirmed: true`.
For each entry in `sinks_found[]` not already covered by a `taint_paths[]` hit at the same file+line (the primary signal in degraded mode): create a lighter pre-candidate — `sink_file`, `sink_line`, `sink_type` only, no traced source — with `cpg_guided: true, cpg_source_confirmed: false`; you still must find and confirm the source yourself.
Do NOT write to `findings.json` yet — confirm via LLM file read in Step 4b first. Preserve `cpg_guided`/`cpg_source_confirmed` through to `findings.json` — `validate-findings`/`scan-report` read them.

### 1.5d — Mark unreachable sinks

Load `unreachable_sinks[]` (always empty in degraded mode). Annotate matching files with `cpg_reachable: false`.
Still analyze (dynamic dispatch, Spring AOP proxies can defeat CPG reachability), but flag findings accordingly.

Print:
```
  CPG taint hints loaded: (degraded: <true/false>)
    Taint paths        : <N>
    Sinks found        : <N>
    Call graph edges   : <N>
    Unreachable sinks  : <N>
    Files re-prioritized: <N>
    CPG candidates     : <N> pre-mapped (<N> full traced, <N> sink-only)
```

---

## Step 2 — Build the scan queue

Analyze files in this priority order:

1. `entry_point` Java files
2. `dao` Java files
3. `service` Java files
4. `filter_interceptor`, `config`, `util` Java files
5. JSP/JSPX files — glob `<repo_path>/src/main/webapp/**/*.jsp`
6. XML config files — `struts.xml`, `web.xml`, `applicationContext.xml`, `persistence.xml`

**Coverage guarantee:** Every file with `security_priority` ≥ 2 (from crawl-output.json) MUST receive at least one full read and analysis pass, regardless of its role tier. Files are processed tier-by-tier and within-tier by descending `security_priority`, but the scan does NOT stop at any tier boundary — all priority ≥ 2 files are reached. Only priority 1 files (boilerplate, generated code, test fixtures) may be skipped. Track and report `files_attempted` and `files_in_manifest` in the output (see Step 6).

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

**Q2 — Authorization and Ownership (IDOR):** Does this method perform a privileged operation?

*Part A — Identity source:* Is the authorization check based on server-side session state (`session.getAttribute("user")`, Spring Security `@PreAuthorize`) or on a client-supplied value (cookie, header, request parameter)? Client-supplied = auth bypass risk.

*Part B — Ownership verification (IDOR):* Does this method accept a resource identifier (path variable `{id}`, `@RequestParam("projectId")`, or body field used as a DB lookup key) and perform a read, update, or delete on that resource?

If yes, check: is the resource's owner field compared against the authenticated session user at any point in this method or the service it calls?

**Ownership IS verified if:**
- `if (!resource.getOwner().equals(currentUser)) throw new ResponseStatusException(FORBIDDEN)`
- Spring Data query scoped by owner: `repository.findByIdAndOwner(id, currentUser)`
- `@PreAuthorize("@resourceService.isOwner(#id, authentication.name)")`

**Ownership is NOT verified if:**
- Only authentication exists: `if (session.getAttribute("user") == null) return 401` — logged in ≠ owns this resource
- Only a role check: `if (!user.hasRole("ADMIN"))` — role ≠ ownership of a specific resource instance
- Resource fetched by ID and returned with no owner comparison

Flag as IDOR (CWE-639) at critical severity for destructive operations, high for private data access, medium for non-sensitive cross-tenant reads.

**Q3 — Crypto:** Does this method hash or compare passwords/tokens? Is the algorithm modern (bcrypt, argon2, PBKDF2)? Is a random salt used?

**Q4 — Sensitive data in logs:** Does this method log passwords, tokens, or keys?

**Q5 — Null safety:** Does a user-triggered lookup return null that is used without a null check?

**Q6 — Outbound data leakage into responses or logs:**
- `response.getWriter().write(e.getMessage())` or `ResponseEntity.body(e.toString())` — raw exception detail sent to caller (CWE-209)
- `response.setHeader(key, internalHeaderValue)` forwarding internal service headers (upstream auth tokens, internal host names) verbatim to the client
- `log.info("token={}", token)` or `log.debug("password={}", password)` — credentials written unconditionally to log output (CWE-532)
- Internal file paths or stack traces in `ResponseStatusException` message exposed to external callers

Flag at medium severity (CWE-209 for responses, CWE-532 for logs).

**Q7 — Dead defensive code (security function never wired up):**

Scan for methods named `sanitize*`, `validate*`, `guard*`, `check*`, `filter*`, `isSafe*`, `redact*` in this file and across `files[]` from crawl-output.json. For each security-named method: search entry_point and service files for callers. If a function has zero production callers:
- Flag at medium severity, confidence 0.90
- Note: "Method `X` in `Y` implements a security control but is never called — one call at the unprotected site would close the gap"
- Spring: also look for `@PreAuthorize` annotations that are defined on base classes but not applied on overriding methods in concrete controllers

**Q8 — Resource exhaustion (user controls computation bounds):**
- `new byte[userSize]` or `new int[userCount]` where size comes from a request param with no upper bound cap (CWE-400)
- `for (int i = 0; i < userCount; i++)` with no `Math.min(userCount, MAX)` guard (CWE-400)
- `Pattern.compile(userPattern)` where `userPattern` is request-derived — ReDoS via complex user-controlled regex (CWE-1333)
- `ZipEntry.getSize()` used to allocate a byte array without verifying against an independent limit — zip-bomb via falsified entry headers (CWE-409)
- `IOUtils.toByteArray(inputStream)` or `stream.readAllBytes()` on a user-supplied stream with no size guard (CWE-400)

Flag at medium severity. Fix: always cap allocations with `Math.min(userSize, MAX_ALLOWED_BYTES)` and never compile user-supplied strings as `Pattern`.

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

**CVSS 3.1 scoring** — For every finding, assign `cvss_vector` and `cvss_score`.

Choose each of the 8 metric values based on this finding's specific attack path:

| Metric | Values | Meaning |
|---|---|---|
| AV (Attack Vector) | N/A/L/P | Network / Adjacent / Local / Physical |
| AC (Attack Complexity) | L/H | Low (reliable exploit) / High (special conditions needed) |
| PR (Privileges Required) | N/L/H | None / Low (any authenticated user) / High (admin) |
| UI (User Interaction) | N/R | None / Required (victim must take an action) |
| S (Scope) | U/C | Unchanged (same security domain) / Changed (cross-component) |
| C (Confidentiality) | H/L/N | High (full read) / Low (partial) / None |
| I (Integrity) | H/L/N | High (full write) / Low (partial) / None |
| A (Availability) | H/L/N | High (full DoS) / Low (degraded) / None |

Use the reference table below to pick a starting vector, then adjust for the specific finding:

| Vulnerability class | Base vector | Score |
|---|---|---|
| RCE — network, no auth | CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H | 9.8 |
| RCE — network, auth required | CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H | 8.8 |
| SQL/JPQL injection — no auth | CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N | 9.1 |
| SQL/JPQL injection — auth required | CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N | 8.1 |
| SSRF — no auth | CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N | 7.5 |
| SSRF — auth required | CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N | 6.5 |
| Stored XSS — auth + UI required | CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N | 5.4 |
| Reflected XSS — no auth + UI required | CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N | 6.1 |
| IDOR — read, auth required | CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N | 6.5 |
| IDOR — write/delete, auth required | CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N | 8.1 |
| Open redirect — no auth, UI required | CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N | 6.1 |
| Auth bypass (client-controlled identity) — no auth | CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N | 9.1 |
| Insecure deserialization — no auth | CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H | 9.8 |
| Weak password hash (MD5/SHA1) | CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N | 5.9 |
| Missing auth on critical function | CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N | 9.1 |
| Sensitive data in logs | CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N | 5.5 |
| Dev/debug mode exposed | CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N | 5.3 |
| Information leakage — error messages | CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N | 5.3 |

Adjustment examples:
- Exploit requires admin access → PR:L → PR:H (score drops ~0.5–2.0)
- Special conditions needed → AC:L → AC:H
- Vulnerability only exploitable locally → AV:N → AV:L
- Struts devMode active — exploitability is higher than default → AC:H → AC:L

`cvss_score` must be consistent with `severity`: Critical 9.0–10.0, High 7.0–8.9, Medium 4.0–6.9, Low 0.1–3.9. If your vector places a finding outside the severity band, prefer the vector and note the discrepancy in `confidence_note`.

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
  "files_attempted": 0,
  "files_in_manifest": 0,
  "files_skipped": [
    { "path": "src/main/java/com/example/generated/Model.java", "reason": "security_priority 1 — generated code" }
  ],
  "findings": [
    {
      "id": "FINDING-001",
      "cwe": "CWE-89",
      "owasp": "A03:2021",
      "severity": "critical",
      "confidence": 0.95,
      "confidence_note": "",
      "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
      "cvss_score": 9.1,
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
  Files attempted : <N> / <total_in_manifest> (<skipped> skipped — priority 1 only)
  Files scanned : <N> Java + <N> JSP + <N> XML
  Findings      : <total> (<critical> critical / <high> high / <medium> medium / <low> low)
  Output        : findings.json
```
