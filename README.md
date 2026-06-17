# sast-skills

LLM-powered SAST pipeline implemented as Claude Code slash commands. Point it at any repository — Java, Python, TypeScript, or polyglot — and it traces vulnerabilities from HTTP entry point to dangerous sink across file boundaries.

No static analysis engine. No pattern matching against CVE lists. Pure semantic reasoning: read the code, follow the data, find where attacker-controlled input reaches a dangerous operation without sanitization.

---

## Pipeline — Ordered Workflow

Each stage answers a more precise question than the previous one and reduces noise for the next.

```
REPO
  │
  ▼
┌─────────────────────────────────────────────────────────────────┐
│  STEP 1 — /crawl                                                │
│                                                                 │
│  • Detect language (Java / Python / TypeScript / polyglot)      │
│  • Classify every file by role:                                 │
│    entry_point, service, dao, model, middleware, config, util   │
│  • Extract all HTTP routes from entry point files               │
│  • Flag security-sensitive dependencies                         │
│                                                                 │
│  OUTPUT → crawl-output.json                                     │
│                                                                 │
│  WHY: You cannot find what you have not mapped. Role            │
│  classification tells find-vulns which files receive user       │
│  input and which files touch dangerous sinks — so it reads      │
│  the right files first instead of scanning everything equally.  │
└────────────────────────────┬────────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│  STEP 2 — /find-vulns                                           │
│                                                                 │
│  • Reads files in priority order:                               │
│    entry_points → daos → services → middleware → config         │
│  • For every method asks:                                       │
│    What enters here? Where does it go? Is there a dangerous     │
│    sink? Is there sanitization between source and sink?         │
│  • Covers ALL vulnerability classes in one pass:                │
│    SSRF, command injection, path traversal, SQLi, XSS,          │
│    auth/IDOR, weak crypto, insecure deserialization, and more   │
│  • Reports only when: source + sink + no effective sanitization │
│  • Never pattern-matches a checklist — derives findings from    │
│    reading the actual code                                      │
│                                                                 │
│  OUTPUT → findings.json (candidate findings)                    │
│                                                                 │
│  WHY: Identifies what COULD be vulnerable. Broad by design —   │
│  some false positives are expected here. That is what           │
│  taint-trace and validate-findings are for.                     │
└────────────────────────────┬────────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│  STEP 3 — /taint-trace                                          │
│                                                                 │
│  • For each candidate finding, reads only the files in that     │
│    finding's call chain — not the whole codebase                │
│  • Crosses file boundaries to verify every hop:                 │
│    entry_point → service → DAO → sink                           │
│  • Marks each finding:                                          │
│    confirmed   — full source-to-sink path verified              │
│    denied      — sanitization found, likely false positive      │
│    partial     — one hop could not be fully verified            │
│  • Adds taint_path[] (step-by-step chain) and                   │
│    sanitization_gaps[] (what protection is absent)              │
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
│  STEP 4 — /validate-findings                                    │
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
│  STEP 5 — /scan-report                                          │
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

4. Outputs written to current directory:
   - `crawl-output.json` — file map with roles and routes
   - `findings.json` — enriched findings with taint paths and scores
   - `scan-results.sarif` — for GitHub Security / VS Code
   - `scan-summary.md` — human-readable report with evidence and fixes

---

## Skills Reference

| Skill | Input | Output | Purpose |
|---|---|---|---|
| `/crawl <repo>` | repo path | `crawl-output.json` | Map files by role, extract routes, detect language |
| `/find-vulns` | `crawl-output.json` | `findings.json` | Find source→sink vulnerabilities across all CWE classes |
| `/taint-trace` | `findings.json` | enriched `findings.json` | Verify cross-file taint paths hop by hop |
| `/validate-findings` | `findings.json` | enriched `findings.json` | Score FP likelihood, deduplicate, rank |
| `/scan-report` | `findings.json` | `scan-results.sarif` + `scan-summary.md` | SARIF and Markdown output with fix hints |
| `/sast-full-scan <repo>` | repo path | all of the above | Orchestrate the full pipeline in one command |
| `/generate-fix <FINDING-ID>` | `findings.json` | unified diff + explanation | Generate a concrete fix for one finding |
| `/scan-metrics` | run artifacts | `sast-metrics.json` | Append precision/recall to scan history |

---

## Vulnerability Classes Covered by find-vulns

`find-vulns` reasons about **all** of these in a single pass using the same source→sink framework:

| Class | CWE | Example sink |
|---|---|---|
| SQL / query injection | CWE-89 | `createQuery()`, `execute()`, string-concatenated JPQL/HQL |
| Command injection | CWE-78 | `Runtime.exec()`, `subprocess.run()`, `ProcessBuilder` |
| Server-Side Request Forgery | CWE-918 | `Repo.clone_from(url)`, `requests.get(url)`, `HttpClient` |
| Path traversal | CWE-22 | `os.path.join()`, `new File(path)`, `open(path)` without guard |
| Cross-site scripting | CWE-79 | `innerHTML`, `dangerouslySetInnerHTML`, `response.write()`, JSP `<%= %>` |
| Insecure auth decision | CWE-285/287 | Auth check on client-supplied header, IDOR |
| Unvalidated redirect | CWE-601 | `sendRedirect(userValue)`, `window.location = param` |
| Weak / missing crypto | CWE-916 | MD5/SHA1 for passwords, unsalted hash |
| Sensitive data in logs | CWE-532 | `logger.info(password)`, `console.log(token)` |
| Insecure deserialization | CWE-502 | `ObjectInputStream.readObject()`, untrusted `fromJson()` |
| Missing auth for critical function | CWE-306 | Admin routes excluded from auth middleware |
| Credential exposure | CWE-522 | Credentials injected into attacker-controlled URL |

---

## Supported Languages

| Language | Framework detection | Entry point markers | Crawl phase |
|---|---|---|---|
| Java | Spring Boot, Spring MVC, Struts, JAX-RS | `@RestController`, `@RequestMapping`, `extends HttpServlet` | Phase 2C |
| Python | FastAPI, Flask, Django | `@router.get/post/...`, `@app.route`, file in `routers/` | Phase 2A |
| TypeScript | React, Next.js | `<Route`, `createBrowserRouter`, Next.js `pages/` | Phase 2B |
| Polyglot | Any combination | Detected automatically by file count (≥ 20% threshold) | 2A + 2B or 2A + 2C |

---

## Output Files

| File | Format | Consumer |
|---|---|---|
| `crawl-output.json` | JSON | find-vulns, taint-trace |
| `findings.json` | JSON — progressively enriched across steps | taint-trace, validate-findings, scan-report, generate-fix |
| `scan-results.sarif` | SARIF 2.1.0 | GitHub Security tab, VS Code SARIF viewer, CI/CD gates |
| `scan-summary.md` | Markdown | Developer review, PR comments, Slack |
| `sast-metrics.json` | JSON (append-only) | Precision/recall trend tracking across scan runs |

---

## Design Principles

**One skill, one job.** `find-vulns` covers all vulnerability classes in one pass. There are no separate "hunt" skills per vulnerability type — that would create maintenance drift and false confidence that a class is covered when the main skill misses it.

**Stateless between steps.** Every skill reads files and writes files. No shared in-memory state. Any step can be re-run independently.

**Semantic reasoning, not pattern matching.** `find-vulns` reads code and reasons about data flow. It does not match against a known-vulnerability checklist. Findings must be derived from reading the code — not from prior knowledge of the target.

**Language-neutral from taint-trace onward.** Once a finding is in `findings.json` with a source, sink, and taint path, all downstream skills are completely language-agnostic.

**Evidence-first.** Every finding has: the exact line of evidence, the full cross-file taint path, the specific sanitization gaps, and a concrete fix. Not just "there might be a bug here."

---

## Examples

```bash
# Full scan — Java repo with precision/recall measurement
/sast-full-scan dvja --ground-truth dvja-ground-truth.MD

# Full scan — Python/FastAPI + React (polyglot)
/sast-full-scan genai-migration-assistant-dev

# Full scan — skip taint trace for a fast first pass
/sast-full-scan my-repo --skip-taint

# Generate a fix for a specific confirmed finding
/generate-fix FINDING-003
```

---

## Requirements

- [Claude Code](https://claude.ai/code) CLI
- A git repository (Claude Code discovers slash commands from `.git` presence)
- No other dependencies — the "engine" is the LLM
