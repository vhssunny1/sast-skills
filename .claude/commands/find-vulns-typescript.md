Scan a TypeScript/JavaScript repository for security vulnerabilities by reasoning about data flow — sources, paths, sinks, and sanitization gaps. Write structured findings to findings.json.

Do NOT pattern-match against a checklist of known bugs. Reason from first principles: what data enters each component or function, where does it go, and what could an attacker do if they controlled it?

## Input

`$ARGUMENTS` format: `[--crawl <path>]`

- `--crawl <path>` — path to `crawl-output.json` (default: `./crawl-output.json`)

---

## Step 1 — Load crawl manifest

Read `crawl-output.json`. Extract `repo_path`, `files[]`, `framework`. If missing, print an error and stop.

---

## Step 2 — Build the scan queue

Analyze files in this priority order:

1. `entry_point` files (pages, route handlers, Express routes, API handlers)
2. `middleware` files
3. `component` files with user-input handling (`onChange`, form state, URL params)
4. `service` files (data fetching, external API calls)
5. `config` files
6. `util` files

Within each tier, read files in descending `security_priority` order (from crawl-output.json) so that files with dangerous rendering patterns (maps, markdown, `innerHTML`, `dangerouslySetInnerHTML`) are scanned first.

**Coverage guarantee:** Every file with `security_priority` ≥ 2 (from crawl-output.json) MUST receive at least one full read and analysis pass, regardless of its role tier. Files are processed tier-by-tier and within-tier by descending `security_priority`, but the scan does NOT stop at any tier boundary — all priority ≥ 2 files are reached. Only priority 1 files (boilerplate, migrations, test fixtures) may be skipped. Track and report `files_attempted` and `files_in_manifest` in the output (see Step 6).

---

## Step 3 — Sources, sinks, and sanitization

### Sources (attacker-controlled data)

**React (client-side):**
- Form `onChange` → component state → rendered output
- `useParams()` — URL path parameters (e.g. `/users/:id`)
- `useSearchParams()` — URL query string
- `location.search`, `window.location.hash`, `document.URL` — raw URL
- `window.name`, `document.referrer` — other browser globals
- `document.cookie` — cookies (if read client-side)

**Next.js:**
- `router.query` — query params in pages
- `context.query` in `getServerSideProps` — SSR query params
- `searchParams` in App Router server components
- `params` in dynamic routes (`[id]/page.tsx`)

**Express/Node (server-side):**
- `req.query.key` — URL query string
- `req.body.key` — parsed request body (JSON, form)
- `req.params.key` — URL path parameters
- `req.headers["header-name"]` — HTTP headers

**DOM (reflected XSS sources):**
- `document.URL`, `document.location.href`, `document.location.search`
- `document.referrer`
- `window.name`

**Cross-language stored-data sources (flag for `/cross-language-taint` to verify):**
- API responses containing data that users can write in the backend (e.g. names, descriptions, notes, titles, addresses, coordinates) — these are stored-XSS candidates when rendered in the browser
- Map marker data from API (latitude, longitude labels, popup content) rendered via `bindPopup()` or `setContent()`
- Any field that the Python/Java backend stores from user input and this frontend renders — the taint path crosses a language boundary

Taint propagates through: variable assignment, template literals, object spread, array access, JSX expression slots, prop drilling.

### Sinks (dangerous operations)

| Sink | Examples | Risk |
|---|---|---|
| DOM XSS | `element.innerHTML = tainted`, `element.outerHTML = tainted`, `document.write(tainted)`, `document.writeln(tainted)`, `insertAdjacentHTML("beforeend", tainted)` | Script execution in victim browser |
| React XSS | `dangerouslySetInnerHTML={{ __html: tainted }}` | Script execution in victim browser |
| Mermaid XSS | `mermaid.initialize({ securityLevel: 'loose' })` + `element.innerHTML = svg` where svg content is from user/LLM | Script execution via diagram injection |
| Code injection | `eval(tainted)`, `new Function(tainted)`, `setTimeout(tainted, n)` with string (not arrow function), `setInterval(tainted, n)` | Arbitrary code execution |
| Open redirect | `window.location.href = tainted`, `window.location = tainted`, `router.push(tainted)` where tainted can be an external URL, `res.redirect(tainted)` (Express) | Phishing, session theft |
| postMessage to any origin | `window.postMessage(data, "*")` — broad target allows cross-origin data theft | Data exfiltration |
| Session cookie exfiltration | `fetch(userControlledUrl, { credentials: 'include' })` — when `url` is attacker-controlled (e.g. from `useSearchParams().get('url')`), the browser sends session cookies to the attacker's server before CORS can block the response. The response body is blocked but the cookies are already delivered. This is distinct from SSRF: the impact is session hijacking, not network probing. Assign HIGH severity. Fix: validate `new URL(url, window.location.origin).origin === window.location.origin` before fetching, or proxy server-side. | Session hijacking via cookie exfiltration |
| SSRF (Node) | `fetch(tainted)`, `axios.get(tainted)`, `node-fetch(tainted)`, `got(tainted)` where URL is user-controlled | Internal network probe |
| Command injection (Node) | `child_process.exec(tainted)`, `child_process.exec(\`cmd ${tainted}\`)`, `child_process.spawn("sh", ["-c", tainted])` | Remote code execution |
| Path traversal (Node) | `fs.readFile(path.join(base, tainted))` without `path.resolve()` + base-containment check, `fs.readFileSync(tainted)`, `res.sendFile(tainted)` | Arbitrary file read |
| SQL injection (Node) | Template literal SQL: `` `SELECT * FROM users WHERE id = ${tainted}` ``, string concatenation in DB query | Data exfiltration |
| Prototype pollution | `Object.assign(target, userControlledObj)` or deep merge where keys are not validated — can corrupt `Object.prototype` | Application logic bypass |
| Mapping library HTML injection | `marker.bindPopup(tainted)`, `layer.setPopupContent(tainted)`, `L.popup().setContent(tainted)` (Leaflet); `new mapboxgl.Popup().setHTML(tainted)` (Mapbox) — mapping libraries render popup content as raw HTML by default | XSS via map popup — user-supplied location names, coordinates, or metadata stored in DB and rendered in browser without sanitization |
| CSS-as-HTML injection | `styleElement.innerHTML = userCss` where `styleElement` is a `<style>` DOM node — assigning user-controlled CSS to a style element's innerHTML allows `</style>` tag injection, which closes the style block and renders arbitrary HTML. A payload like `</style><img src=x onerror=alert(1)>` executes JavaScript. | Stored XSS — dashboard CSS, theme CSS, user-defined styles stored in DB and injected at render time |
| Outbound response leakage (Node/Express) | `res.json({ error: err.message })` returning raw exception message; `res.set(upstreamResponse.headers)` forwarding internal service headers to client; `console.log(process.env.SECRET_KEY)` in request handler; `res.setHeader("X-Internal-Path", filePath)` leaking server file paths | Internal system information exposed to external clients — stack traces, credentials, internal hostnames |

### Sanitization that breaks the chain

- `DOMPurify.sanitize(tainted)` before `innerHTML` — breaks DOM XSS
- `mermaid.initialize({ securityLevel: 'strict' })` — breaks Mermaid XSS
- `DOMPurify.sanitize(svg, { USE_PROFILES: { svg: true } })` before `innerHTML` — breaks Mermaid XSS
- **React JSX default encoding** — `<div>{tainted}</div>` is safe; React encodes text content. ONLY `dangerouslySetInnerHTML` is dangerous.
- `encodeURIComponent(tainted)` — breaks some open redirect if destination is a param, not the whole URL; NOT sufficient if tainted controls the base URL
- `new URL(tainted)` + `.hostname` check against allowlist — breaks open redirect and SSRF
- Parameterized queries (Prisma model methods, Knex `?` placeholders, `pg` with `$1`) — breaks SQL injection
- `path.resolve(path.join(base, tainted))` + checking result starts with `base` — breaks path traversal
- Content Security Policy (reduces XSS impact but does not prevent the vulnerability)
- **Not sanitization:** `encodeURI()` (does not encode `'`, `"`, `<`, `>`), null/undefined checks, `typeof` checks, `Array.isArray()`
- **Not sanitization — catch-true anti-pattern:** A URL/scheme validation function where the `catch` block returns `true` or a permissive value is a bypass, not protection:
  ```js
  // VULNERABLE — exception path returns "allowed"
  function isAllowedScheme(url: string): boolean {
    try { new URL(url); return true; }
    catch { return true; }  // parsing failure → allow
  }
  ```
  `new URL("//evil.com")` throws in some environments; the catch block's `return true` makes protocol-relative URLs bypass the check entirely. When reviewing URL/scheme validation functions, always check what the `catch` branch returns.
- **Not sanitization — self-documented incomplete sanitizers:** If a CSS or HTML sanitization function has a comment like "not a complete XSS sanitizer" or "does not protect against all injection", treat it as absent sanitization for the purposes of finding confidence scoring. Read the function's own documentation.
- **Not sanitization — custom sanitizers that escape the wrong characters:** When a custom function is called before an HTML sink (e.g. `sanitizeMermaid(code)` before `innerHTML`), read its body and verify it escapes the characters relevant to the sink type. A function that only escapes `{` and `}` (e.g. brace escaping for template syntax) provides zero XSS protection because `<`, `>`, `"`, and `'` remain unescaped. Only treat a custom function as sanitization if it demonstrably converts `<` → `&lt;` and `>` → `&gt;` (for HTML sinks) or applies `DOMPurify.sanitize()`. If in doubt, read the function — do not assume from its name.

---

## Step 4 — Analyze each file

For every file in the scan queue, read the full file, then ask:

**Q1 — Taint (injection / XSS):** What are the inputs (URL params, form data, API responses, DOM sources)? What sinks are in the body? Does any tainted value reach a DOM-writing sink, eval, or redirect without effective sanitization?

**Q2 — Authorization and Ownership (IDOR):**

*Part A — Client-side auth bypass:* Does this component control visibility of privileged features based on a client-stored value (localStorage, cookie, URL param)? Client-side-only auth checks are always bypassable.

*Part B — Server-side ownership check (Node/Express handlers):* Does this handler accept a resource identifier (`id`, `projectId`, `userId`, `docId`, or any `*Id` / `*Uuid` path or query param) and perform a DB operation with it?

If yes, check: is the resource's owner field compared against the authenticated session's identity before or after the operation?

**Ownership IS verified if:**
- `if (resource.ownerId !== req.user.id) return res.status(403).json(...)` 
- ORM query scoped by owner: `.findOne({ where: { id, ownerId: req.user.id } })`
- Prisma: `prisma.project.findFirst({ where: { id, ownerEmail: session.user.email } })`

**Ownership is NOT verified if:**
- Only authentication middleware runs: `if (!req.user) return 401` — authenticated ≠ owns this resource
- Only a role check: `if (req.user.role !== 'admin')` — role ≠ ownership of a specific instance
- Resource is fetched by ID and returned with no owner comparison

Flag as IDOR (CWE-639) when a resource ID parameter is used in a DB operation with no ownership comparison. Severity: critical for destructive operations; high for private data reads or writes; medium for non-sensitive cross-tenant access.

**Q3 — External requests:** Does this component or Node handler fetch from a URL that is partially or fully user-controlled? Is the URL scheme and host validated before the request?

**Q4 — Sensitive data exposure:** Are API keys, JWTs, or secrets hard-coded in client-side code or included in client-side bundles (e.g. `process.env.SECRET_KEY` in a React component)?

**Q5 — Prototype pollution:** Are object spread or merge operations performed on user-controlled keys without key validation?

**Q6 — Security validation catch blocks:** When you find a function whose name or purpose is to validate URLs, schemes, or hostnames (e.g. `isAllowedScheme`, `isSafeUrl`, `isValidHost`, `checkRedirect`), read the full function including its `catch` / `except` block. If the catch block:
- returns `true`, `"allow"`, or calls `next()` without restriction — the exception path bypasses the validation (catch-true anti-pattern)
- returns `false` or throws — the function is safe on the exception path

Flag catch-true as CWE-601 (open redirect) or CWE-918 (SSRF) at medium severity with confidence 0.80.

**Q7 — Outbound data leakage into responses or logs:** Does this handler or component leak sensitive system information back to the client or to logs?

Look for (Node/Express server-side):
- `res.json({ error: err.message })` or `res.send(err.stack)` — raw exception details returned to caller (CWE-209)
- `res.set(proxyResponse.headers)` or `res.setHeader(key, internalValue)` forwarding internal service headers (auth tokens, trace IDs, upstream hostnames) verbatim to the external client
- `console.log(process.env.API_KEY)` or `console.log(req.headers.authorization)` in a request handler — tokens or credentials written to stdout unconditionally
- `res.setHeader("X-Log-File", logFilePath)` — internal file paths in response headers

Look for (React client-side):
- `console.log(token)` or `console.log(apiResponse)` where `apiResponse` may contain secrets — visible to any user with browser devtools
- Storing JWTs or API keys in `localStorage` and rendering them in the DOM (exposure to XSS)

Flag with CWE-209 (error message information exposure) at medium severity when exceptions are returned raw; CWE-200 (information exposure) for internal paths and headers in responses.

**Q8 — Dead defensive code (security function never wired up):** Are security utility functions defined but never called on production paths?

Scan the file and cross-reference `files[]` from crawl-output.json for functions named:
`sanitize*`, `validate*`, `guard*`, `check*`, `filter*`, `isSafe*`, `redact*`, `escape*`, `purify*`

For each: search all entry_point and component files in crawl-output.json for calls to that function. If zero callers exist on production code paths:
- Flag at medium severity, confidence 0.90 (CWE-1041 / CWE-116)
- Note: "Function `X` exists in `Y` but is never called — adding one call at the unprotected render site would close the gap"

**Q9 — Resource exhaustion (user controls computation bounds in Node):**

Look for:
- `fs.readFileSync(userFile)` or `fs.readFile(userFile)` with no size cap before reading — unbounded memory allocation (CWE-400)
- `for (let i = 0; i < userCount; i++)` or `Array(userCount).fill(...)` with no `Math.min(userCount, MAX)` guard (CWE-400)
- `new RegExp(userPattern)` or `new RegExp(userPattern, flags)` where `userPattern` is request-derived — user-controlled regex evaluated against large corpus is a ReDoS vector (CWE-1333)
- Streaming responses: `res.write()` in a loop driven by user-controlled iteration count with no back-pressure check (CWE-400)

Flag at medium severity. Fix: always cap loops with `Math.min(userCount, MAX_ALLOWED)` and never compile user-supplied strings as regex patterns.

---

## Step 5 — Score, deduplicate, assign IDs

**Confidence:**
- 0.90–1.00 — source and sink in same file/component, direct taint, no sanitization visible
- 0.70–0.89 — one prop or variable hop between source and sink
- 0.50–0.69 — indirect path, cross-component, sanitization may exist in parent
- < 0.50 — discard

**Filter:** ≥ 0.70 report; 0.50–0.69 report with `confidence_note: "indirect — verify manually"`.

**Deduplicate:** same CWE + same file + same line ±3 → keep higher confidence.

**Number:** `FINDING-001`, `FINDING-002`, ...

**CWE/OWASP mapping:**

| Class | CWE | OWASP |
|---|---|---|
| DOM XSS / React XSS | CWE-79 | A03:2021 |
| Code injection (eval) | CWE-94 | A03:2021 |
| Command injection (Node) | CWE-78 | A03:2021 |
| SQL injection (Node) | CWE-89 | A03:2021 |
| Session cookie exfiltration via fetch | CWE-918 | A10:2021 |
| SSRF (Node fetch) | CWE-918 | A10:2021 |
| Path traversal (Node fs) | CWE-22 | A01:2021 |
| Open redirect | CWE-601 | A01:2021 |
| Client-side auth bypass | CWE-285 | A01:2021 |
| IDOR / missing ownership check | CWE-639 | A01:2021 |
| Prototype pollution | CWE-1321 | A03:2021 |
| Hardcoded credentials in client | CWE-798 | A02:2021 |
| Sensitive data in client bundle | CWE-200 | A02:2021 |

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
| SQL injection — no auth | CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N | 9.1 |
| SQL injection — auth required | CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N | 8.1 |
| NoSQL injection — auth required | CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N | 8.1 |
| XXE — network, no auth | CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N | 7.5 |
| SSRF — no auth | CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N | 7.5 |
| SSRF — auth required | CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N | 6.5 |
| Stored XSS — auth + UI required | CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N | 5.4 |
| Reflected XSS — no auth + UI required | CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N | 6.1 |
| IDOR — read, auth required | CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N | 6.5 |
| IDOR — write/delete, auth required | CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N | 8.1 |
| Open redirect — no auth, UI required | CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N | 6.1 |
| Hardcoded secret — network exploitable | CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N | 9.1 |
| Hardcoded secret — source code access required | CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N | 7.7 |
| Path traversal — read, auth required | CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N | 6.5 |
| Path traversal — write, auth required | CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N | 8.1 |
| Insecure deserialization — no auth | CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H | 9.8 |
| Weak password hash (MD5/SHA1) | CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N | 5.9 |
| Supply chain (curl\|sh, no hash check) | CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H | 9.0 |
| Unpinned dependency (mutable tag/ref) | CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H | 8.1 |
| Prompt injection (indirect, LLM-mediated) | CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N | 4.8 |
| Information leakage — error messages | CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N | 5.3 |
| Password exposed in GET params | CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N | 6.5 |

Adjustment examples:
- Exploit requires admin access → PR:L → PR:H (score drops ~0.5–2.0)
- Special conditions needed (race, specific config) → AC:L → AC:H
- Vulnerability only exploitable locally → AV:N → AV:L
- Cross-component impact (XSS reaches a different security domain) → S:U → S:C

`cvss_score` must be consistent with `severity`: Critical 9.0–10.0, High 7.0–8.9, Medium 4.0–6.9, Low 0.1–3.9. If your vector places a finding outside the severity band, prefer the vector and note the discrepancy in `confidence_note`.

---

## Step 6 — Write findings.json

Write to `findings.json` in the current working directory. Overwrite if exists.

```json
{
  "scanned_at": "<ISO 8601>",
  "repo_path": "<absolute path>",
  "language": "typescript",
  "crawl_input": "./crawl-output.json",
  "total_findings": 0,
  "files_attempted": 42,
  "files_in_manifest": 45,
  "files_skipped": [
    { "path": "src/generated/api.ts", "reason": "security_priority 1 — generated code" }
  ],
  "findings_by_severity": { "critical": 0, "high": 0, "medium": 0, "low": 0 },
  "findings": [
    {
      "id": "FINDING-001",
      "cwe": "CWE-79",
      "owasp": "A03:2021",
      "severity": "medium",
      "confidence": 0.75,
      "confidence_note": "",
      "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N",
      "cvss_score": 4.8,
      "file": "frontend/src/components/chat/ChatComponent.tsx",
      "line": 6,
      "method": "mermaid.initialize",
      "source": "LLM response mermaid code blocks — reachable via prompt injection through analyzed repo content",
      "sink": "ref.current.innerHTML = svg — unsanitized mermaid SVG injected into DOM (line 47)",
      "sanitization_present": "sanitizeMermaid() escapes {} only — no XSS protection",
      "evidence": "mermaid.initialize({ startOnLoad: false, theme: 'neutral', securityLevel: 'loose' } as any)",
      "description": "Mermaid initialized with securityLevel:'loose' disables HTML sanitization in node labels. SVG is injected via innerHTML without DOMPurify. Prompt injection through malicious repo content can cause JS execution in the user's browser.",
      "fix_hint": "Change securityLevel to 'strict', or sanitize the SVG with DOMPurify.sanitize(svg, { USE_PROFILES: { svg: true } }) before innerHTML assignment."
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
- `source` must name the specific variable, prop, or API call introducing user-controlled data.
- `sink` must name the specific dangerous DOM operation or Node API call.
- Do not consult ground truth files, CVE lists, or prior knowledge of this codebase. Findings must come from reading the code.

---

## Completion

```
find-vulns-typescript complete.
  Repo          : <repo_path>
  Files scanned : <N> TypeScript + <N> JavaScript files
  Files attempted: <N> / <total_in_manifest> (<skipped> skipped — priority 1 only)
  Findings      : <total> (<critical> critical / <high> high / <medium> medium / <low> low)
  Output        : findings.json
```
