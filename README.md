# sast-skills

LLM-powered SAST pipeline implemented as Claude Code slash commands. Point it at any repository — Java, Python, TypeScript, or polyglot — and it traces vulnerabilities from HTTP entry point to dangerous sink across file boundaries.

No static analysis engine. No pattern matching against CVE lists. Pure semantic reasoning: read the code, follow the data, find where attacker-controlled input reaches a dangerous operation without sanitization.

---

## How It Works

```
/crawl          Detect language, classify files by role, extract HTTP routes
    ↓
/find-vulns     Read entry points → services → DAOs. Reason source → sink → sanitization.
    ↓
/taint-trace    Cross file boundaries. Verify each hop in the call chain.
    ↓
/validate-findings  Score false-positive likelihood. Rank. Suppress noise.
    ↓
/scan-report    SARIF 2.1.0 for tooling. Markdown with evidence, taint path, fix code.
```

Or run the whole pipeline in one command:

```
/sast-full-scan <repo-path> [--ground-truth <file>]
```

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
   - `findings.json` — enriched findings with taint paths
   - `scan-results.sarif` — for GitHub Security / VS Code
   - `scan-summary.md` — human-readable report with fixes

---

## Skills Reference

### Pipeline Skills (run in order)

| Skill | Input | Output | Purpose |
|---|---|---|---|
| `/crawl <repo>` | repo path | `crawl-output.json` | Map files, routes, dependencies |
| `/find-vulns` | `crawl-output.json` | `findings.json` | Identify source→sink vulnerabilities |
| `/taint-trace` | `findings.json` | enriched `findings.json` | Verify cross-file taint paths |
| `/validate-findings` | `findings.json` | enriched `findings.json` | Score FP likelihood, rank findings |
| `/scan-report` | `findings.json` | `scan-results.sarif` + `scan-summary.md` | Generate SARIF and Markdown report |
| `/sast-full-scan <repo>` | repo path | all of the above | Orchestrate full pipeline |
| `/generate-fix <FINDING-ID>` | `findings.json` | unified diff + explanation | Generate a concrete fix for one finding |
| `/scan-metrics` | run artifacts | `sast-metrics.json` | Append precision/recall to history |

### Targeted Hunt Skills (run independently)

These focus on a single vulnerability class and can be run without the full pipeline.

| Skill | What it looks for |
|---|---|
| `/ssrf-hunt` | Server-Side Request Forgery — URLs built from user input passed to HTTP clients |
| `/cmd-injection` | Command injection — user input reaching subprocess, exec, shell calls |
| `/path-traversal` | Path traversal — user-supplied filenames used in file path construction |
| `/auth-audit` | Authentication/authorization gaps — header-based identity, IDOR, missing ownership checks |
| `/frontend-hunt` | Frontend XSS — innerHTML, dangerouslySetInnerHTML, eval, unsafe markdown rendering |
| `/waf-bypass` | WAF bypass patterns — encoding tricks, HTTP header smuggling, parameter pollution |
| `/sandbox-escape` | Sandbox/container escape vectors — privileged operations, host mounts, capability abuse |

---

## Supported Languages

| Language | Framework detection | Entry point markers | Sink vocabulary |
|---|---|---|---|
| Java | Spring Boot, Spring MVC, Struts, JAX-RS | `@RestController`, `@RequestMapping`, `extends HttpServlet` | `createQuery()`, `Runtime.exec()`, JSP output |
| Python | FastAPI, Flask, Django | `@router.get/post/...`, `@app.route`, file in `routers/` | `subprocess.run()`, `os.path.join()`, `Repo.clone_from()` |
| TypeScript | React, Next.js | `<Route`, `createBrowserRouter`, Next.js `pages/` | `innerHTML`, `dangerouslySetInnerHTML`, `eval()` |
| Polyglot | Any combination | Detected automatically by file count | Both language vocabularies applied |

---

## Output Files

| File | Format | Consumer |
|---|---|---|
| `crawl-output.json` | JSON | find-vulns, taint-trace |
| `findings.json` | JSON (progressively enriched) | taint-trace, validate-findings, scan-report, generate-fix |
| `scan-results.sarif` | SARIF 2.1.0 | GitHub Security tab, VS Code SARIF viewer, CI/CD |
| `scan-summary.md` | Markdown | Developer review, PR comments, Slack |
| `sast-metrics.json` | JSON (append-only) | Trend tracking across scan runs |

---

## Design Principles

**Stateless between steps.** Every skill reads files and writes files. No shared in-memory state. Any step can be re-run independently.

**Semantic reasoning, not pattern matching.** find-vulns reads code and reasons about data flow. It does not match against a known-vulnerability checklist. Findings must be derived from the code, not from prior knowledge of the target.

**Language-neutral from taint-trace onward.** Once a finding is in `findings.json` with a source, sink, and taint path, all downstream skills are completely language-agnostic.

**Evidence-first.** Every finding has: the exact line of evidence, the full cross-file taint path, the specific sanitization gaps, and a concrete fix. Not just "there might be a bug here."

---

## Example: Running Against DVJA (Java)

```
/sast-full-scan dvja --ground-truth dvja-ground-truth.MD
```

## Example: Running Against a FastAPI + React App (Polyglot)

```
/sast-full-scan genai-migration-assistant-dev
```

## Example: Targeted SSRF Hunt

```
/ssrf-hunt /path/to/repo
```

---

## Requirements

- [Claude Code](https://claude.ai/code) CLI
- A git repository (Claude Code discovers slash commands from `.git` presence)
- No other dependencies — the "engine" is the LLM
