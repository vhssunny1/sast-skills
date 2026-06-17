Hunt a JavaScript/TypeScript frontend for trust boundary violations and DOM injection vulnerabilities. Reason from first principles — trace data flow, validate origin checks, and audit sanitization logic. Write structured findings to frontend-findings.json.

Do NOT pattern-match a checklist of known bug names. Reason from first principles: where does attacker-controlled data enter, where does it go, and what security boundary does it cross?

## Background: Why This Skill Exists

Standard SAST tools (Semgrep, ESLint security plugins) find known sink patterns but are blind to:
- Whether a postMessage handler validates `event.origin` (browser-enforced) vs `event.data.origin` (attacker-controlled)
- Whether a DOMPurify config uses a safe allowlist vs an incomplete blocklist
- Whether an `unsafeHTML` call is upstream from attacker-supplied data
- Business logic that lets an attacker trigger a privileged action via a cross-origin message

This skill fills that gap using semantic reasoning.

## Input

`$ARGUMENTS` format: `[--repo <path>] [--framework <name>]`

- `--repo <path>` — path to the frontend source root (default: current directory)
- `--framework <name>` — hint: `react | lit | vue | angular | vanilla` (auto-detected if omitted)

## Step 1 — Detect Framework and Map the Surface

Read `package.json` at the repo root. Extract:
- Framework: look for `lit`, `react`, `vue`, `@angular/core` in dependencies
- Build tool: vite, webpack, esbuild, rollup
- Note any security-relevant packages: `dompurify`, `sanitize-html`, `xss`, `trusted-types`

Glob for all `.ts`, `.tsx`, `.js`, `.jsx` files. Exclude:
- `node_modules/`, `dist/`, `build/`, `.storybook/`, `coverage/`, `*.test.*`, `*.spec.*`, `*.stories.*`

If total file count exceeds 500, print a warning and ask for a narrower path.

## Step 2 — Understand the 5 Vulnerability Classes Before Reading Any File

Internalize these before analysis. Apply them throughout.

### Class 1 — postMessage Origin Confusion (CWE-346)

A `message` event listener is only safe if it validates `event.origin` (browser-enforced, reflects the actual sender's origin). Checking `event.data.source`, `event.data.origin`, or any field INSIDE the message payload is NOT safe — attackers control the payload.

**SOURCE:** Any cross-origin window, iframe, or popup can send arbitrary postMessages.

**SINK:** Any action taken inside a `message` event listener that has real effect:
- Submitting a form / calling `submit()`
- Navigating (`location.href = ...`)
- Storing tokens or credentials
- Executing code (`eval`, dynamic script injection)
- Triggering UI state changes that bypass user interaction

**SANITIZATION (genuine):** `if (event.origin !== window.location.origin) return;` or `if (!ALLOWED_ORIGINS.includes(event.origin)) return;`

**SANITIZATION (ineffective — still vulnerable):**
- `if (event.data.source !== "myapp") return;` — attacker controls `event.data`
- `if (event.data.origin !== "trusted") return;` — attacker controls `event.data`
- `if (event.data.type !== "expected") return;` — attacker controls `event.data`

**For each `addEventListener("message", ...)` or `window.onmessage` found:**
1. Read the handler body
2. Identify what action is taken when the message matches
3. Determine whether `event.origin` is checked BEFORE taking that action
4. If only `event.data.*` fields are checked: finding

---

### Class 2 — Unsanitized HTML Injection (CWE-79)

Directly assigning attacker-controlled strings to HTML-rendering APIs executes JavaScript.

**SINKS:**
- `element.innerHTML = x`
- `element.outerHTML = x`
- `document.write(x)`
- Lit: `unsafeHTML(x)`, `unsafeStatic(x)`
- React: `dangerouslySetInnerHTML={{ __html: x }}`
- Vue: `v-html="x"`
- jQuery: `.html(x)`, `.append(x)` with HTML strings
- `document.createRange().createContextualFragment(x)`

**SOURCES (attacker-controlled values):**
- URL parameters: `location.search`, `location.hash`, `URLSearchParams`
- `postMessage` payloads (especially when origin not validated — see Class 1)
- API responses that include user-generated content (usernames, comments, descriptions, display names, bio, annotation metadata, file names)
- `localStorage`, `sessionStorage` values set from API data
- Third-party / federated identity claims (name, email fields from OAuth tokens)

**SANITIZATION (genuine):** Value passed through `DOMPurify.sanitize(x, { ALLOWED_TAGS: [...] })` with an allowlist config, OR through a safe text-only API (`textContent`, `createTextNode`).

**SANITIZATION (insufficient):**
- `DOMPurify.sanitize(x, { FORBID_TAGS: [...], FORBID_ATTR: [...] })` — blocklist approach. Flag these for Class 3 analysis.
- Sanitization on a different code path than the sink
- Sanitization that only strips `<script>` but leaves event handlers

**For each sink found:**
1. Trace the value upstream — is it a constant, server-supplied config, or user-generated content?
2. If user-generated: is it sanitized with an allowlist before reaching the sink?
3. If no allowlist sanitization: finding

---

### Class 3 — Incomplete Sanitization Config (CWE-116)

`DOMPurify.sanitize()` is safe only when configured with an allowlist (`ALLOWED_TAGS`, `ALLOWED_ATTR`). A blocklist (`FORBID_TAGS`, `FORBID_ATTR`) is always incomplete.

**Blocklist gaps — common missed event handlers:**
`onkeydown`, `onkeyup`, `onkeypress`, `onpaste`, `oncopy`, `oncut`, `onpointerdown`, `onpointerup`, `onpointermove`, `onpointerenter`, `onpointerleave`, `oninput`, `onchange`, `onfocusin`, `onfocusout`, `ondrag`, `ondrop`, `ondragstart`, `ondragend`, `onanimationstart`, `onanimationend`, `ontransitionend`, `onscroll`, `onresize`, `oncontextmenu`, `onwheel`, `onsecuritypolicyviolation`, `ontouchstart`, `ontouchend`, `ontouchmove`

**For each `DOMPurify.sanitize()` or equivalent call found:**
1. Check if config uses `ALLOWED_TAGS` / `ALLOWED_ATTR` (allowlist) — SAFE
2. Check if config uses `FORBID_TAGS` / `FORBID_ATTR` (blocklist) — check for gaps above
3. Check if config uses neither (default DOMPurify) — SAFE for most cases but note it
4. If blocklist is used: test mentally — can `<img src=x onpointerdown="alert(1)">` pass through?

---

### Class 4 — Frontend Open Redirect (CWE-601)

Navigation to attacker-controlled URLs allows phishing and token theft.

**SINKS:**
- `window.location.href = x`
- `window.location.replace(x)`
- `window.location.assign(x)`
- `window.open(x)`
- Router `navigate(x)`, `push(x)`, `redirect(x)`
- `<a href>` or `<iframe src>` set from dynamic values

**SOURCES:**
- `location.search` / `URLSearchParams` (especially `?next=`, `?redirect=`, `?url=`, `?return=`)
- `postMessage` payloads
- API responses

**SANITIZATION (genuine):** `new URL(x).origin === window.location.origin` check before navigation, OR only using path components (not full URLs) for redirect.

**SANITIZATION (insufficient):**
- `x.startsWith("https://")` — attacker can use `https://evil.com`
- `x.includes("myapp.com")` — attacker can use `https://evil.com?myapp.com`
- Only checking the first characters

---

### Class 5 — Prototype Pollution (CWE-1321)

Merging attacker-controlled objects into plain objects can poison `Object.prototype`.

**SINKS:**
- `Object.assign({}, userInput)`
- `{ ...userInput }` spread when `userInput` comes from `JSON.parse()`
- Recursive merge functions: `merge(target, source)` without `__proto__` filtering
- `lodash.merge`, `deepmerge`, `jquery.extend(true, ...)` with attacker input

**SOURCE:** JSON from `postMessage` payloads, URL query parameters parsed as JSON, API responses that allow nested objects.

**SANITIZATION (genuine):** `JSON.parse(JSON.stringify(x))` before merging (strips prototype), or explicit `__proto__` / `constructor` key filtering.

---

## Step 3 — Build the Scan Queue

Prioritize files in this order:

1. **postMessage handlers** — glob for files containing `addEventListener.*message` or `onmessage`
2. **HTML injection sinks** — glob for files containing `innerHTML`, `unsafeHTML`, `dangerouslySetInnerHTML`, `v-html`, `document.write`
3. **Sanitization configs** — glob for files containing `DOMPurify`, `sanitize-html`, `sanitizeHTML`, `FORBID_TAGS`, `FORBID_ATTR`
4. **Navigation sinks** — glob for files containing `location.href`, `location.replace`, `window.open`, `router.navigate`
5. **URL param sources** — glob for files containing `URLSearchParams`, `location.search`, `location.hash`
6. **OAuth/Auth callbacks** — glob for files containing `access_token`, `id_token`, `code=` in URL handling context

Skip files over 3000 lines (add to `skipped_files`).

## Step 4 — Analyze Each File

For every file in the scan queue, read it fully, then apply the relevant class analysis.

### 4a — postMessage Handlers (Class 1)

Read the full handler function. Answer:

> **Question 1:** What action does this handler take when a matching message is received? Is the action privileged (submit, navigate, store auth data, execute code)?

> **Question 2:** Before taking that action, does the code read `event.origin`? Is `event.origin` compared against a trusted value?

> **Question 3:** If the code reads `event.data.source`, `event.data.origin`, or any other field from inside the payload to decide whether to act — this is NOT an origin check. The attacker controls `event.data`. Flag this.

> **Question 4:** Can an attacker who controls a cross-origin page (or opens this page as a popup via `window.open()`) send a message that triggers the privileged action?

If yes to Q4: finding.

### 4b — HTML Injection Sinks (Class 2)

For each `innerHTML`, `unsafeHTML`, `dangerouslySetInnerHTML`, etc.:

> **Question 1:** What is the value being rendered? Trace it backward — constant, server config, or user-generated content?

> **Question 2:** If user-generated: does the value pass through an allowlist sanitizer before reaching the sink?

> **Question 3:** Is the sanitizer called on THIS code path (not just somewhere else in the codebase)?

> **Question 4:** Could a federated identity claim (username, display name, email, annotation author) reach this sink?

If user-generated data reaches the sink without allowlist sanitization: finding.

### 4c — Sanitization Configs (Class 3)

For each `DOMPurify.sanitize()` or equivalent:

> **Question 1:** Does the config use `ALLOWED_TAGS` (allowlist)? → safe, skip.

> **Question 2:** Does the config use `FORBID_TAGS` or `FORBID_ATTR` (blocklist)? → check gaps.

> **Question 3:** Test mentally: can `<img src=x onpointerdown="alert(1)">` pass through? Can `<a href="#" onkeydown="evil()">` pass through? If yes: finding.

> **Question 4:** Is this sanitizer applied to content that an admin or external user can control? If yes and blocklist: finding.

### 4d — Navigation Sinks (Class 4)

For each navigation sink:

> **Question 1:** What is the URL being navigated to? Trace it upstream.

> **Question 2:** If it comes from `location.search`/`hash` or a `postMessage` payload: is the full origin validated before use?

> **Question 3:** Is the check a real origin comparison, or a string prefix/contains check?

If URL comes from user input without origin validation: finding.

### 4e — Prototype Pollution (Class 5)

For each merge/spread with user-supplied objects:

> **Question 1:** Is `__proto__` or `constructor.prototype` filtered before the merge?

> **Question 2:** Can an attacker supply `{"__proto__": {"isAdmin": true}}` and have it propagate?

If no filtering: finding.

## Step 5 — Score, Filter, and Assign IDs

**Assign confidence:**

- **0.90–1.00** — Source and sink are in the same function; taint is direct; no origin check or sanitization visible in the function
- **0.70–0.89** — Source and sink separated by one hop (prop/variable pass); sanitization may exist in a related file but is not verified on this path
- **0.50–0.69** — Indirect path requiring cross-file reasoning; sanitization may exist elsewhere
- **< 0.50** — Speculative; do not report

**Filter:**
- ≥ 0.70 → report as finding
- 0.50–0.69 → report with `"confidence_note": "indirect path — verify manually"`
- < 0.50 → discard

**Number sequentially:** `FH-001`, `FH-002`, ...

**Assign CWE and class:**

| Class | CWE | Description |
|---|---|---|
| postMessage origin confusion | CWE-346 | Origin Validation Error |
| innerHTML/unsafeHTML injection | CWE-79 | Cross-site Scripting |
| DOMPurify blocklist bypass | CWE-116 | Improper Encoding or Escaping |
| Frontend open redirect | CWE-601 | URL Redirection to Untrusted Site |
| Prototype pollution | CWE-1321 | Improperly Controlled Object Prototype |

**Severity:**

| Severity | Criteria |
|---|---|
| Critical | Direct XSS with no user interaction required; postMessage bypass that submits auth-bypassing payload |
| High | Stored XSS reachable by regular users; postMessage that forces privileged action (consent bypass, form submit) |
| Medium | Reflected XSS requiring user action; open redirect; blocklist bypass reachable by admins |
| Low | Prototype pollution with limited gadgets; DOMPurify misconfiguration not currently reachable by user input |

## Step 6 — Deduplicate

If two findings identify the same vulnerability class in the same file at the same line (±5 lines), keep only the higher-confidence one.

## Step 7 — Write frontend-findings.json

Write to `frontend-findings.json` in the current working directory. Overwrite if exists.

## Output Schema

```json
{
  "scanned_at": "<ISO 8601 timestamp>",
  "repo_path": "<absolute path>",
  "framework": "lit | react | vue | angular | vanilla",
  "total_findings": 0,
  "findings_by_severity": {
    "critical": 0,
    "high": 0,
    "medium": 0,
    "low": 0
  },
  "findings": [
    {
      "id": "FH-001",
      "class": "postMessage origin confusion | html injection | sanitization bypass | open redirect | prototype pollution",
      "cwe": "CWE-346",
      "severity": "critical | high | medium | low",
      "confidence": 0.95,
      "confidence_note": "",
      "file": "src/flow/controllers/FlowIframeMessageController.ts",
      "line": 38,
      "handler_or_function": "onMessage",
      "source": "event.data.source — attacker-controlled field inside the message payload",
      "sink": "this.host.submit({}) — submits the active flow stage with empty payload",
      "origin_check_present": "Checks event.data.source === 'goauthentik.io' — NOT a real origin check",
      "evidence": "if (source === \"goauthentik.io\" && context === \"flow-executor\" && message === \"submit\")",
      "attack_scenario": "Any cross-origin page opens this app as a popup via window.open(), then sends {source:'goauthentik.io',context:'flow-executor',message:'submit'} — forces submission of the active flow stage with no user interaction",
      "description": "The message handler validates a field inside the attacker-controlled payload (event.data.source) instead of the browser-enforced event.origin. An attacker from any origin can forge this field and trigger the privileged submit action.",
      "fix_hint": "Add 'if (event.origin !== window.location.origin) return;' as the first line of the handler before inspecting event.data."
    }
  ],
  "skipped_files": [
    { "path": "...", "reason": "exceeds line limit | binary | unreadable" }
  ],
  "warnings": []
}
```

## Hard Rules

- Report only what you can see in the code you read. Do not invent findings.
- `evidence` must be a verbatim line or minimal snippet from the file (trimmed of leading whitespace only).
- `source` must name the specific variable or call that introduces attacker-controlled data.
- `sink` must name the specific operation that creates a security impact.
- `origin_check_present` must describe what check IS present (even if insufficient) — or "none".
- `attack_scenario` must describe a concrete, realistic scenario — not just "attacker can exploit".
- Do not flag `unsafeHTML` / `innerHTML` that renders only hardcoded strings, translated strings (`msg()`), or values from a trusted server-side config not editable by regular users.
- Do not flag `DOMPurify` configured with `ALLOWED_TAGS` (allowlist) — that is the correct pattern.
- `postMessage` handlers that validate `event.origin` correctly are NOT findings. Confirm the check exists before skipping.

## Downstream Consumers

- `/auth-audit` reads `frontend-findings.json` to cross-reference with backend auth bypass paths
- `/frontend-poc` reads `frontend-findings.json` and generates proof-of-concept HTML for each finding
- `/disclosure-draft` reads `frontend-findings.json` and writes a responsible disclosure advisory

## Completion

```
frontend-hunt complete.
  Repo          : <repo_path>
  Framework     : <framework>
  Files scanned : <N> TypeScript + <N> JavaScript
  Findings      : <total> (<critical> critical / <high> high / <medium> medium / <low> low)
  Output        : frontend-findings.json
```
