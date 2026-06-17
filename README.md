# sast-skills

LLM-powered SAST pipeline implemented as Claude Code slash commands. Point it at any repository — Java, Python, TypeScript, or polyglot — and it traces vulnerabilities from HTTP entry point to dangerous sink across file boundaries.

No static analysis engine. No pattern matching against CVE lists. Pure semantic reasoning: read the code, follow the data, find where attacker-controlled input reaches a dangerous operation without sanitization.

---

## Pipeline — Ordered Workflow

Language is detected first. Then language-specific skills map the codebase and find vulnerabilities. The final three steps are language-neutral.

```
REPO
  │
  ▼
┌─────────────────────────────────────────────────────────────────┐
│  STEP 0 — /detect-language                                      │
│                                                                 │
│  • Counts file extensions across the repo                       │
│  • Reads config files: pom.xml, requirements.txt, package.json  │
│  • Identifies significant languages (≥ 20% of files or ≥ 15)   │
│  • Detects framework per language (Spring Boot, FastAPI, React) │
│  • Outputs which crawl-* and find-vulns-* skills to run next    │
│                                                                 │
│  OUTPUT → language-manifest.json                                │
│                                                                 │
│  WHY: crawl and find-vulns need language-specific instructions. │
│  A Java crawl looks for @Controller; a Python crawl looks for   │
│  @router.get. Running the wrong one produces empty output.      │
└────────────────────────────┬────────────────────────────────────┘
                             │
              ┌──────────────┼──────────────┐
              ▼              ▼              ▼
        crawl-java     crawl-python   crawl-typescript
              └──────────────┼──────────────┘
                             │  (merged if polyglot)
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│  STEP 1 — /crawl-<language>                                     │
│                                                                 │
│  • Classify every file by role:                                 │
│    entry_point, service, dao, model, middleware, config, util   │
│  • Extract all HTTP routes from entry point files               │
│  • Flag security-sensitive dependencies                         │
│  • For polyglot: multiple skills run, outputs are merged        │
│                                                                 │
│  OUTPUT → crawl-output.json                                     │
│                                                                 │
│  WHY: Role classification tells find-vulns which files receive  │
│  user input and which touch dangerous sinks — so it reads the   │
│  right files first instead of scanning everything equally.      │
└────────────────────────────┬────────────────────────────────────┘
                             │
              ┌──────────────┼──────────────┐
              ▼              ▼              ▼
        find-vulns-   find-vulns-   find-vulns-
             java         python      typescript
              └──────────────┼──────────────┘
                             │  (merged if polyglot)
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│  STEP 2 — /find-vulns-<language>                                │
│                                                                 │
│  • Language-specific sources, sinks, and sanitization rules     │
│  • Reads files in priority order:                               │
│    entry_points → middleware → daos → services → config         │
│  • For every method asks:                                       │
│    What enters here? Where does it go? Is there a dangerous     │
│    sink? Is there sanitization between source and sink?         │
│  • Never pattern-matches a checklist — derives findings from    │
│    reading the actual code                                      │
│                                                                 │
│  OUTPUT → findings.json (candidate findings)                    │
│                                                                 │
│  WHY: Language-specific skills know the exact source/sink APIs. │
│  Python's subprocess.run() and Java's Runtime.exec() are the   │
│  same vulnerability class but need different code patterns.     │
└────────────────────────────┬────────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│  STEP 3 — /taint-trace          (language-neutral)              │
│                                                                 │
│  • For each candidate finding, reads only the files in that     │
│    finding's call chain — not the whole codebase                │
│  • Crosses file boundaries to verify every hop:                 │
│    entry_point → service → DAO → sink                           │
│  • Marks each finding:                                          │
│    confirmed   — full source-to-sink path verified              │
│    denied      — sanitization found, likely false positive      │
│    partial     — one hop could not be fully verified            │
│  • Adds taint_path[] and sanitization_gaps[]                    │
│                                                                 │
│  OUTPUT → findings.json (enriched in place)                     │
│                                                                 │
│  WHY: A finding with a 1-file path is a guess. A finding with   │
│  a verified 8-hop chain across 6 files is a confirmed           │
│  vulnerability. This is what separates SAST from grep.          │
└────────────────────────────┬────────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│  STEP 4 — /validate-findings    (language-neutral)              │
│                                                                 │
│  • Deduplicates findings with same CWE + file + line (±5)       │
│  • Scores each finding: fp_score 0.0 (real) → 1.0 (false pos.) │
│    taint_confirmed: true   → −0.40                              │
│    confidence ≥ 0.90       → −0.20                              │
│    cross-file path ≥ 2     → −0.10                              │
│    taint_confirmed: null   → +0.20                              │
│    low confidence scores   → +0.15 to +0.20                     │
│  • Assigns validation_status:                                   │
│    confirmed / likely_real / needs_review / likely_fp           │
│  • Ranks by severity → fp_score → confidence                    │
│                                                                 │
│  OUTPUT → findings.json (enriched in place)                     │
│                                                                 │
│  WHY: Makes suppression explicit and auditable. Developers      │
│  only see findings that passed the bar — and they can see       │
│  exactly why each finding was included or filtered out.         │
└────────────────────────────┬────────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│  STEP 5 — /scan-report          (language-neutral)              │
│                                                                 │
│  • SARIF 2.1.0 → GitHub Security tab, VS Code, CI/CD           │
│  • Markdown → developer review, PR comments, Slack             │
│  • Per finding: evidence line, full taint path, fix code        │
│  • Recommendations grouped by ROOT CAUSE, not by file           │
│  • Precision / recall table if ground truth is provided         │
│                                                                 │
│  OUTPUT → scan-results.sarif + scan-summary.md                  │
│                                                                 │
│  WHY: Findings that stay in JSON are useless. Root-cause        │
│  grouping reveals "fix one thing, eliminate four findings."     │
│  SARIF plugs into every standard security toolchain.            │
└─────────────────────────────────────────────────────────────────┘
```

**Key design rule:** Each step writes a file; the next step reads it. No shared memory between steps. Any step can be re-run independently without re-running the whole pipeline.

---

## Quick Start

1. Clone this repo into your project or workspace:
   ```bash
   git clone https://github.com/vhssunny1/sast-skills.git
   cd sast-skills
   ```

2. Open in Claude Code (requires `.git` — already present after clone).

3. Run against any target repository:
   ```
   /sast-full-scan /path/to/target-repo
   ```

4. Outputs written to `sast-runs/<timestamp>/`:
   - `language-manifest.json` — detected languages and routing decisions
   - `crawl-output.json` — file map with roles and routes
   - `findings.json` — enriched findings with taint paths and scores
   - `scan-results.sarif` — for GitHub Security / VS Code
   - `scan-summary.md` — human-readable report with evidence and fixes

---

## Skills Reference

### Orchestrator

| Skill | Purpose |
|---|---|
| `/sast-full-scan <repo>` | Run the full pipeline. Detects language, routes to the right skills, merges polyglot outputs. |

### Language detection

| Skill | Output | Purpose |
|---|---|---|
| `/detect-language <repo>` | `language-manifest.json` | Identify languages, frameworks, and which pipeline skills to run |

### Crawl (language-specific)

| Skill | Language | Entry point markers | Framework detection |
|---|---|---|---|
| `/crawl-java <repo>` | Java / Kotlin | `@Controller`, `@RestController`, `extends HttpServlet` | Spring Boot, Spring MVC, Struts, JAX-RS via pom.xml |
| `/crawl-python <repo>` | Python | `@router.get/post/...`, `@app.route`, files in `routers/` | FastAPI, Flask, Django via requirements.txt |
| `/crawl-typescript <repo>` | TypeScript / JS | `<Route`, `createBrowserRouter`, Next.js `pages/`, `app.get(` | Next.js, React, Express, Vue via package.json |

### Find vulnerabilities (language-specific)

| Skill | Language | Key sources | Key sinks |
|---|---|---|---|
| `/find-vulns-java` | Java | Struts setters, `@RequestParam`, `request.getParameter()` | `createQuery()`, `Runtime.exec()`, JSP `<%= %>` |
| `/find-vulns-python` | Python | FastAPI `Form(...)`, `request.headers.get()`, Flask `request.args` | `subprocess.run()`, `Repo.clone_from()`, `pickle.loads()`, `eval()` |
| `/find-vulns-typescript` | TypeScript / JS | `useParams()`, `req.query`, `document.URL`, `dangerouslySetInnerHTML` | `innerHTML`, `eval()`, `child_process.exec()`, `fs.readFile()` |

### Language-neutral (run after find-vulns, regardless of language)

| Skill | Input | Output | Purpose |
|---|---|---|---|
| `/taint-trace` | `findings.json` | enriched `findings.json` | Verify cross-file taint paths hop by hop |
| `/validate-findings` | `findings.json` | enriched `findings.json` | Score FP likelihood, deduplicate, rank |
| `/scan-report` | `findings.json` | `scan-results.sarif` + `scan-summary.md` | SARIF and Markdown output with fix hints |
| `/generate-fix <FINDING-ID>` | `findings.json` | unified diff + explanation | Generate a concrete fix for one finding |
| `/scan-metrics` | run artifacts | `sast-metrics.json` | Append precision/recall to scan history |

---

## Vulnerability Classes Covered

Each `find-vulns-*` skill reasons about all of these using the same source→sink framework, applied to the idioms of its language:

| Class | CWE | Java sink example | Python sink example | TypeScript sink example |
|---|---|---|---|---|
| SQL injection | CWE-89 | `createQuery("..." + val)` | `db.execute(f"...{val}")` | `` `SELECT ${val}` `` |
| Command injection | CWE-78 | `Runtime.exec(val)` | `subprocess.run([val])` | `child_process.exec(val)` |
| SSRF | CWE-918 | `HttpClient.get(val)` | `requests.get(val)`, `Repo.clone_from(val)` | `fetch(val)` |
| Path traversal | CWE-22 | `new File(base, val)` | `open(os.path.join(base, val))` | `fs.readFile(path.join(base, val))` |
| XSS | CWE-79 | JSP `<%= val %>` | Jinja2 `{{ val \| safe }}` | `element.innerHTML = val` |
| Insecure auth | CWE-285/287 | Auth on cookie value | Auth on `request.headers.get()` | Auth on localStorage |
| Insecure deserialization | CWE-502 | `ObjectInputStream.readObject()` | `pickle.loads(val)`, `yaml.load(val)` | `eval(val)` |
| Credential exposure | CWE-522 | Credentials in URL string | `f"https://{user}:{token}@{val}"` | API key in client bundle |
| Missing auth | CWE-306 | Admin routes excluded from filter | Admin routes excluded from middleware | Client-side-only auth check |
| Weak crypto | CWE-916 | `MessageDigest.getInstance("MD5")` | `hashlib.md5(password)` | `crypto-js` MD5 for passwords |
| Sensitive data in logs | CWE-532 | `logger.info(password)` | `logger.debug(token)` | `console.log(apiKey)` |
| Open redirect | CWE-601 | `response.sendRedirect(val)` | `redirect(val)` | `window.location.href = val` |

---

## Supported Languages

| Language | Skills | Notes |
|---|---|---|
| Java | `crawl-java` + `find-vulns-java` | Spring Boot, Spring MVC, Struts, JAX-RS |
| Python | `crawl-python` + `find-vulns-python` | FastAPI, Flask, Django |
| TypeScript / JS | `crawl-typescript` + `find-vulns-typescript` | React, Next.js, Express, Node |
| Polyglot | Multiple skills, outputs merged | e.g. Python backend + React frontend runs both Python and TypeScript skills |

---

## Output Files

| File | Format | Consumer |
|---|---|---|
| `language-manifest.json` | JSON | sast-full-scan routing |
| `crawl-output.json` | JSON | find-vulns-*, taint-trace |
| `findings.json` | JSON — progressively enriched | taint-trace, validate-findings, scan-report, generate-fix |
| `scan-results.sarif` | SARIF 2.1.0 | GitHub Security tab, VS Code SARIF viewer, CI/CD gates |
| `scan-summary.md` | Markdown | Developer review, PR comments, Slack |
| `sast-metrics.json` | JSON (append-only) | Precision/recall trend tracking across runs |

---

## Design Principles

**Language-specific skills, language-neutral pipeline.** `crawl` and `find-vulns` are split by language so each skill knows the exact source/sink APIs for its ecosystem. `taint-trace`, `validate-findings`, and `scan-report` are language-neutral — a confirmed taint path looks the same regardless of what language it came from.

**Detect first, route second.** `detect-language` runs before anything else and explicitly names which skills to invoke. No guessing inside crawl or find-vulns about what language they are dealing with.

**One file per step.** Every skill reads files and writes files. No shared in-memory state. Any step can be re-run independently.

**Semantic reasoning, not pattern matching.** `find-vulns-*` skills read code and reason about data flow. They do not match against a known-vulnerability checklist. Findings must be derived from reading the code — not from prior knowledge of the target.

**Evidence-first.** Every finding has: the exact line of evidence, the full cross-file taint path, the specific sanitization gaps, and a concrete fix.

---

## Examples

```bash
# Java repo with precision/recall measurement
/sast-full-scan dvja --ground-truth dvja-ground-truth.MD

# Python/FastAPI + React (polyglot — auto-detected, both skill sets run)
/sast-full-scan genai-migration-assistant-dev

# Fast first pass — skip taint trace
/sast-full-scan my-repo --skip-taint

# Generate a fix for a specific confirmed finding
/generate-fix FINDING-003

# Run individual steps
/detect-language my-repo
/crawl-python my-repo
/find-vulns-python --crawl crawl-output.json
```

---

## Requirements

- [Claude Code](https://claude.ai/code) CLI
- A git repository (Claude Code discovers slash commands from `.git` presence)
- No other dependencies — the "engine" is the LLM
