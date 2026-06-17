Hunt a codebase for Server-Side Request Forgery vulnerabilities — from user-controlled URL inputs through server-side fetch, render, and import pipelines. Trace data flow. Reason about what internal resources become accessible. Write structured findings to ssrf-findings.json.

Do NOT flag every `requests.get(url)` as a finding. The URL must be traceable to attacker-controlled input without effective validation. Reason about what the SSRF enables — cloud metadata, internal APIs, file read — not just that the call exists.

## Background: Why This Skill Exists

SSRF is invisible to pattern-based SAST because the dangerous call (`requests.get`, `fetch`, `http.get`) is often legitimate. What matters is whether attacker-controlled input reaches it. Novee found a Full Read SSRF in WebViewer Server through an iframe rendering endpoint — the attack surface was a file-rendering feature, not an obvious "fetch URL" field.

This skill traces the full path: entry point → URL construction → outbound request → what it accesses.

## Input

`$ARGUMENTS` format: `[--repo <path>] [--lang <python|go|java|node>]`

- `--repo <path>` — repo root (default: current directory)
- `--lang <name>` — auto-detected if omitted

## Step 1 — Map the Attack Surface

SSRF lives in server-side features that make outbound requests. Find these entry points first.

**High-value surfaces (where Novee and real-world SSRF CVEs live):**

| Surface | Why It's High Value |
|---|---|
| File/document rendering | Server fetches a URL embedded in a PDF/HTML/SVG to render it |
| iframe `src` parameter | Server-side renderer follows iframe URLs |
| Webhook configuration | Admin/user provides a URL the server will POST to |
| OAuth provider URLs | `authorization_url`, `token_url`, `jwks_uri` configured by admin |
| Import / fetch by URL | "Import from URL", "load remote resource" features |
| Image/avatar URL fetch | Server-side image proxy or resizing |
| DNS-based features | Anything that resolves hostnames server-side |
| LDAP / SMTP server URLs | Connection targets configured by users |
| XML/SVG external entities | XXE as a class of SSRF |

Glob for these patterns based on language:

**Python:** `requests.get`, `requests.post`, `urllib.request`, `httpx.get`, `aiohttp`, `urllib.urlopen`
**Go:** `http.Get`, `http.NewRequest`, `http.Do`
**Java:** `URL.openConnection`, `HttpURLConnection`, `OkHttpClient`, `RestTemplate`, `WebClient`
**Node:** `fetch(`, `axios.get`, `http.request`, `https.request`, `got(`
**General:** `curl_exec`, `file_get_contents` (PHP), `Net::HTTP` (Ruby)

Also glob for rendering-related patterns: `iframe`, `srcdoc`, `<img src`, `svg`, `xmllint`, `wkhtmltopdf`, `puppeteer`, `playwright`, `chromium`, `headless`.

## Step 2 — The 5 SSRF Vulnerability Classes

---

### Class 1 — Direct URL Parameter SSRF

User supplies a full URL → server fetches it.

**Source:** Any parameter that accepts a URL or URI:
- Query string: `?url=`, `?src=`, `?path=`, `?endpoint=`, `?webhook=`, `?target=`, `?link=`, `?file=`
- Request body field named `url`, `uri`, `endpoint`, `target`, `src`, `href`, `link`, `webhook`
- HTTP header: `X-Forwarded-For`, custom headers used as URLs

**Sink:** Any server-side HTTP request using that value

**Sanitization (genuine):**
- Allowlist of permitted domains checked AFTER URL parsing (not string prefix)
- Block of private IP ranges using a proper IP range check (not string comparison)
- URL parsed with `urlparse`/`new URL()` and only `hostname` is used — not the full URL

**Sanitization (insufficient):**
- `url.startswith("https://")` — doesn't block `https://169.254.169.254`
- `"internal" not in url` — string-based domain checks are trivially bypassed
- Checking the hostname before DNS resolution — DNS rebinding bypasses this
- Blocking `localhost` but not `127.0.0.1`, `0.0.0.0`, `[::1]`, `0177.0.0.1`

**For each outbound HTTP call with a URL from user input:**
1. Trace the URL back to its source — is it user-supplied?
2. Is there a validation step? Does it use proper URL parsing + IP range checks?
3. Can the check be bypassed with `0.0.0.0`, `[::]`, `http://127.1`, decimal IP, octal IP, DNS rebinding?
4. What internal resources does this server have access to? (cloud metadata at 169.254.169.254, internal APIs, other services)

---

### Class 2 — Indirect SSRF via File / Document Rendering

Server renders a user-supplied document that contains embedded URLs the renderer follows.

**Attack vectors:**
- SVG with `<image href="http://internal/">` or `<use href="http://...">` — renderers follow these
- HTML with `<iframe src="...">` or `<img src="...">` — headless browser fetches them
- PDF with external links, embedded fonts, form actions pointing to internal URLs
- XML with external entity declarations (`<!ENTITY ext SYSTEM "http://internal/">`) — XXE
- CSS with `@import url("http://...")` or `background-image: url("http://...")`
- Markdown with `![img](http://internal/)` rendered server-side

**Sink:** Any server-side renderer: wkhtmltopdf, puppeteer, playwright, LibreOffice, ImageMagick, Pillow, xmllint, lxml with network loading enabled

**Sanitization (genuine):**
- Renderer configured with `--disable-local-file-access` AND network access disabled
- SVG/XML parsed with external entity loading disabled: `resolve_entities=False`, `XMLParser(no_network=True)`
- Input sanitized with allowlist HTML cleaner before passing to renderer

**For each file rendering pipeline:**
1. Does the renderer follow external URLs (headless browser, SVG renderer with network)?
2. Is the input document sanitized before rendering — are embedded URLs stripped?
3. Is the renderer sandboxed from the internal network?

---

### Class 3 — SSRF via Admin-Configurable URLs

Admin-provided URLs (OAuth endpoints, LDAP servers, SMTP, webhooks) that the server connects to.

These are lower severity because admin access is required — but they become critical when:
- The feature is accessible to non-admin users
- Admin is a separate persona from server operator (SaaS model)
- SSRF enables reading internal service responses (full-read SSRF)

**Common patterns:**
- OAuth source `authorization_url`, `access_token_url`, `jwks_uri` — server makes outbound requests to these
- LDAP source `server_uri` — server connects to this host
- SMTP `host` — server connects for sending email
- Webhook `url` — server POSTs to this URL on events
- "Import from URL" — server fetches this URL

**For each admin-configurable URL that the server connects to:**
1. Is there validation of what hosts can be configured?
2. Can an admin point this at `http://169.254.169.254/latest/meta-data/` (AWS metadata)?
3. Can a non-admin influence this configuration?
4. Does the server return the response body to the requester (full-read SSRF)?

---

### Class 4 — DNS Rebinding and IP Check Bypass

Even when there IS an IP allowlist/blocklist, DNS rebinding can bypass it.

**Pattern:**
1. Server validates `hostname` → DNS resolves to public IP → check passes
2. Server makes the actual request → DNS resolves to `127.0.0.1` (TTL expired, attacker changed it)

**Conditions for DNS rebinding:**
- Server resolves DNS for validation SEPARATELY from the actual connection
- Server does not pin the resolved IP for the connection

**Also check for IP representation bypasses:**
- Decimal IP: `2130706433` = `127.0.0.1`
- Octal: `0177.0.0.1`
- Hex: `0x7f000001`
- IPv6: `::1`, `::ffff:127.0.0.1`
- Short form: `127.1`
- IPv6-mapped IPv4: `[::ffff:169.254.169.254]`

**For each IP validation function:**
1. Does it parse the URL, resolve DNS, check the IP — or just string-match the hostname?
2. Does it cover all IP representation formats above?
3. Is the resolved IP pinned for the actual connection?

---

### Class 5 — SSRF Response Exposure (Full-Read vs. Blind)

Not all SSRFs are equal. The real impact depends on whether the server returns the fetched content.

**Full-read SSRF (critical):**
- Response body returned to the attacker: `return requests.get(url).text`
- Error messages that leak response content: `except Exception as e: return str(e)`
- Redirect following with response proxied back

**Blind SSRF (high):**
- Server makes the request but returns no content
- Impact: port scanning, internal service enumeration, triggering webhooks

**Time-based SSRF (medium):**
- Different response times for open vs closed ports

**For each SSRF finding from Classes 1–4:**
1. Does the server return the fetched content to the user?
2. Does the server leak any information from the response (status code, error message, timing)?

---

## Step 3 — Build the Scan Queue

Priority order:
1. Files containing outbound HTTP calls (`requests`, `fetch`, `http.get`, etc.)
2. Files containing file/document rendering calls
3. Files containing URL parameters accepted from user input
4. Config/model files defining URL fields for OAuth sources, webhooks, SMTP, LDAP
5. XML/SVG processing files

## Step 4 — Analyze Each File

Read the full file. Apply the relevant class.

**For each outbound HTTP call:**
> Q1: Trace the URL argument upstream. What is its source? User input, admin config, hardcoded, env var?
> Q2: If user-supplied: what validation runs before the call? Does it use proper URL parsing + IP blocking?
> Q3: What can this call reach? Same VPC, cloud metadata, internal APIs, file system via `file://`?
> Q4: Is the response returned to the caller?

**For each rendering pipeline:**
> Q1: What format is being rendered? Can it contain external references (URLs, entities)?
> Q2: Is external reference loading disabled in the renderer's config?
> Q3: Is the input sanitized before rendering?

## Step 5 — Score and Filter

**Confidence:**
- **0.90–1.00** — URL directly from request parameter, no validation, full-read response
- **0.70–0.89** — URL from request but behind a validation that has a bypass
- **0.50–0.69** — Admin-configurable URL with no non-admin path; or indirect rendering SSRF
- **< 0.50** — Discard

**Number:** `SS-001`, `SS-002`, ...

**Severity:**

| Severity | Criteria |
|---|---|
| Critical | Full-read SSRF reachable by unauthenticated or low-privilege users |
| High | Full-read SSRF requires admin; or blind SSRF reaching cloud metadata |
| Medium | Blind SSRF reachable by users; admin SSRF with limited internal exposure |
| Low | Admin SSRF to same-origin only; rendering SSRF in isolated sandbox |

## Step 6 — Write ssrf-findings.json

```json
{
  "scanned_at": "<ISO 8601 timestamp>",
  "repo_path": "<absolute path>",
  "total_findings": 0,
  "findings_by_severity": { "critical": 0, "high": 0, "medium": 0, "low": 0 },
  "findings": [
    {
      "id": "SS-001",
      "class": "direct-url-param | render-pipeline | admin-configurable | dns-rebinding | response-exposure",
      "cwe": "CWE-918",
      "severity": "critical | high | medium | low",
      "confidence": 0.90,
      "confidence_note": "",
      "file": "authentik/sources/oauth/clients/oauth2.py",
      "line": 111,
      "function": "get_access_token",
      "source": "self.source.access_token_url — admin-configured OAuth source URL",
      "sink": "self.do_request('post', access_token_url, ...) — server-side HTTP POST",
      "validation_present": "None — URL is used as-configured with no host restriction",
      "internal_targets": "Cloud metadata at 169.254.169.254, internal APIs on VPC",
      "response_exposure": "Full-read — response.json() returned to caller",
      "attack_scenario": "Admin configures an OAuth source with access_token_url pointing to http://169.254.169.254/latest/meta-data/iam/security-credentials/. Server POSTs to this URL and returns the JSON response, leaking cloud credentials.",
      "description": "The OAuth source access_token_url is used directly in a server-side HTTP request with no host validation. An admin can point this at internal infrastructure.",
      "fix_hint": "Validate that the URL host resolves to a public IP before connecting. Block RFC1918 ranges, loopback, and link-local addresses."
    }
  ],
  "skipped_files": [],
  "warnings": []
}
```

## Hard Rules

- Do not flag outbound calls to hardcoded URLs or environment-variable URLs (these are not attacker-controlled).
- `internal_targets` must name specific realistic targets for this deployment type — not just "internal network".
- `response_exposure` must state whether the response is returned, partially leaked, or blind.

## Completion

```
ssrf-hunt complete.
  Repo          : <repo_path>
  Lang          : <language>
  Files scanned : <N>
  Findings      : <total> (<critical> critical / <high> high / <medium> medium / <low> low)
  Output        : ssrf-findings.json
```
