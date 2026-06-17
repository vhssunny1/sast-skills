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
| SSRF (Node) | `fetch(tainted)`, `axios.get(tainted)`, `node-fetch(tainted)`, `got(tainted)` where URL is user-controlled | Internal network probe |
| Command injection (Node) | `child_process.exec(tainted)`, `child_process.exec(\`cmd ${tainted}\`)`, `child_process.spawn("sh", ["-c", tainted])` | Remote code execution |
| Path traversal (Node) | `fs.readFile(path.join(base, tainted))` without `path.resolve()` + base-containment check, `fs.readFileSync(tainted)`, `res.sendFile(tainted)` | Arbitrary file read |
| SQL injection (Node) | Template literal SQL: `` `SELECT * FROM users WHERE id = ${tainted}` ``, string concatenation in DB query | Data exfiltration |
| Prototype pollution | `Object.assign(target, userControlledObj)` or deep merge where keys are not validated — can corrupt `Object.prototype` | Application logic bypass |
| Mapping library HTML injection | `marker.bindPopup(tainted)`, `layer.setPopupContent(tainted)`, `L.popup().setContent(tainted)` (Leaflet); `new mapboxgl.Popup().setHTML(tainted)` (Mapbox) — mapping libraries render popup content as raw HTML by default | XSS via map popup — user-supplied location names, coordinates, or metadata stored in DB and rendered in browser without sanitization |

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

---

## Step 4 — Analyze each file

For every file in the scan queue, read the full file, then ask:

**Q1 — Taint (injection / XSS):** What are the inputs (URL params, form data, API responses, DOM sources)? What sinks are in the body? Does any tainted value reach a DOM-writing sink, eval, or redirect without effective sanitization?

**Q2 — Authorization (client-side):** Does this component control visibility of privileged features based on a client-stored value (localStorage, cookie, URL param)? Client-side-only auth checks are always bypassable.

**Q3 — External requests:** Does this component or Node handler fetch from a URL that is partially or fully user-controlled? Is the URL scheme and host validated before the request?

**Q4 — Sensitive data exposure:** Are API keys, JWTs, or secrets hard-coded in client-side code or included in client-side bundles (e.g. `process.env.SECRET_KEY` in a React component)?

**Q5 — Prototype pollution:** Are object spread or merge operations performed on user-controlled keys without key validation?

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
| SSRF (Node fetch) | CWE-918 | A10:2021 |
| Path traversal (Node fs) | CWE-22 | A01:2021 |
| Open redirect | CWE-601 | A01:2021 |
| Client-side auth bypass | CWE-285 | A01:2021 |
| Prototype pollution | CWE-1321 | A03:2021 |
| Hardcoded credentials in client | CWE-798 | A02:2021 |
| Sensitive data in client bundle | CWE-200 | A02:2021 |

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
  "findings_by_severity": { "critical": 0, "high": 0, "medium": 0, "low": 0 },
  "findings": [
    {
      "id": "FINDING-001",
      "cwe": "CWE-79",
      "owasp": "A03:2021",
      "severity": "medium",
      "confidence": 0.75,
      "confidence_note": "",
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
  Findings      : <total> (<critical> critical / <high> high / <medium> medium / <low> low)
  Output        : findings.json
```
