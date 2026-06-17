Find stored-XSS and injection paths that cross language boundaries — specifically where a Python (or Java) backend stores user-controlled data and a TypeScript/JavaScript frontend renders it without sanitization.

This skill runs AFTER find-vulns in polyglot repos (Python/Java + TypeScript). Single-language scans miss these flows entirely because each language scanner only sees one side of the boundary.

## Input

`$ARGUMENTS` format: `[--findings <path>] [--crawl <path>]`

- `--findings <path>` — path to `findings.json` (default: `./findings.json`)
- `--crawl <path>` — path to `crawl-output.json` (default: `./crawl-output.json`)

---

## Why this matters

A typical stored-XSS path across language boundaries:

```
User submits data via POST /api/items
    ↓  [Python Flask/Django/FastAPI view]
Stored in database as-is (no output encoding — Python doesn't know it'll be rendered as HTML)
    ↓  [Database]
Returned in GET /api/items response as JSON
    ↓  [TypeScript React/Vue component]
Rendered via marker.bindPopup(item.name)   ← Leaflet renders as raw HTML
         OR  element.innerHTML = item.description
         OR  dangerouslySetInnerHTML={{ __html: item.body }}
```

Neither the Python scanner nor the TypeScript scanner sees the full path alone.

---

## Step 1 — Load inputs

Read `findings.json` and `crawl-output.json`.

Extract from `findings.json`:
- All Python/Java findings with `source` containing "DB", "stored", "user-supplied", "query result", or where `sink` mentions writing to a database column that is user-writable
- All TypeScript findings already flagged with `confidence_note` containing "cross-language" or `source` mentioning "API response"

Extract from `crawl-output.json`:
- Python/Java `entry_point` and `dao` files — these are where data is stored
- TypeScript `component` and `service` files — these are where data is rendered

---

## Step 2 — Identify backend store points

Read Python/Java DAO and entry_point files to find where user-controlled data is written to the database.

A store point is: a DB write operation (INSERT, UPDATE, ORM `.save()`, `.create()`, `.add()`) where the value being stored came from user input without output-encoding for HTML.

**Key insight:** Python/Flask/Django stores data as strings. String content is not HTML-encoded at storage time because the backend does not know the data will be rendered as HTML later. Output encoding is the frontend's responsibility. When the frontend skips it, stored XSS occurs.

For each store point, record:
- Table/model name and column
- Which HTTP endpoint writes it (e.g. `POST /api/markers` stores `name`, `lat`, `lng`, `description`)
- Whether there is any validation that restricts HTML/JavaScript content (e.g. Pydantic validator blocking `<script>`)

---

## Step 3 — Identify frontend render points

Read TypeScript component and service files to find where API data is rendered without sanitization.

Focus on these render patterns:

| Pattern | Risk |
|---|---|
| `marker.bindPopup(item.name)` — Leaflet | HTML rendered in map popup |
| `layer.setPopupContent(item.description)` — Leaflet | HTML rendered in map popup |
| `new mapboxgl.Popup().setHTML(data.content)` — Mapbox | HTML rendered in map popup |
| `element.innerHTML = response.data.title` | DOM XSS |
| `dangerouslySetInnerHTML={{ __html: item.body }}` | React XSS |
| `v-html="item.content"` | Vue XSS |
| Template literal in `innerHTML`: `` element.innerHTML = `<div>${item.name}</div>` `` | DOM XSS |

For each render point, record:
- Which API endpoint's response field is being rendered
- Whether `DOMPurify.sanitize()` or equivalent is applied before rendering

---

## Step 4 — Match store points to render points

For each render point, check:

1. Does the rendered field come from an API endpoint that stores user-controlled data (Step 2)?
2. Is there sanitization at either the store point (backend validation rejecting HTML) OR the render point (DOMPurify before innerHTML)?

If both conditions are true (user-controlled data flows from storage to raw HTML rendering with no sanitization on either side), create a cross-language finding.

**Confidence scoring:**
- 0.90–1.00 — You read both the backend store code and the frontend render code; field names match; no sanitization on either side
- 0.70–0.89 — You read one side; the other side is inferred from API response field names or component prop names
- 0.50–0.69 — Indirect match (field names don't exactly match but the data flow is plausible)

---

## Step 5 — Write cross-language findings

Append to `findings.json`. Use prefix `XL-` for cross-language finding IDs:

```json
{
  "id": "XL-001",
  "cwe": "CWE-79",
  "owasp": "A03:2021",
  "severity": "high",
  "confidence": 0.85,
  "confidence_note": "Backend store confirmed; frontend render inferred from API field name match",
  "file": "client/app/components/map/MapView.tsx",
  "line": 47,
  "method": "renderMarkers",
  "source": "GET /api/map/markers response — marker.name field, originally stored from POST /api/map/markers without HTML validation",
  "sink": "marker.bindPopup(m.name) — Leaflet renders popup content as raw HTML",
  "sanitization_present": "none — no DOMPurify on frontend; no HTML-rejecting validator on backend",
  "evidence": "marker.bindPopup(m.name)",
  "description": "User-supplied marker names are stored in the database via POST /api/map/markers (Python backend) and rendered as raw HTML via Leaflet's bindPopup() in the TypeScript frontend. An attacker who creates a marker with a name like <img src=x onerror=alert(1)> will execute JavaScript in every browser that views the map.",
  "fix_hint": "Frontend: wrap the value with DOMPurify.sanitize() before bindPopup(): marker.bindPopup(DOMPurify.sanitize(m.name)). Backend: add a Pydantic validator that strips or rejects HTML tags in the name field.",
  "language_boundary": {
    "backend_file": "api/handlers/map.py",
    "backend_line": 34,
    "backend_method": "create_marker",
    "backend_operation": "INSERT into markers (name, lat, lng) — name is user-supplied, no HTML validation",
    "frontend_file": "client/app/components/map/MapView.tsx",
    "frontend_line": 47,
    "frontend_method": "renderMarkers",
    "frontend_operation": "marker.bindPopup(m.name) — Leaflet renders as HTML"
  },
  "condition": null
}
```

---

## Hard rules

- Do NOT add findings where you cannot identify both a backend store point AND a frontend render point from code you actually read
- `language_boundary` is required for all XL findings — both sides must be cited
- Do not flag API fields where the backend applies allowlist validation that rejects HTML content (e.g. `regex: r'^[a-zA-Z0-9 ]+$'`)
- Do not flag React JSX text interpolation (`{item.name}`) — React encodes text content by default. Only `dangerouslySetInnerHTML`, `innerHTML`, and mapping library popup methods are dangerous.

---

## Completion

```
cross-language-taint complete.
  Store points found : <N> backend endpoints writing user data to DB
  Render points found: <N> frontend components rendering API data as HTML
  Matched paths      : <N> cross-boundary taint paths
  Findings created   : <N> (XL-001, XL-002, ...)
  Output             : findings.json (appended)
```
