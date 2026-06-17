Detect the primary language(s) of a repository and write a routing manifest for the SAST pipeline. This is always the first step — its output tells sast-full-scan which crawl and find-vulns skills to invoke.

## Input

`$ARGUMENTS` format: `<repo-path>`

- `<repo-path>` — required. Absolute or relative path to the repository root.

If no path provided, print usage and stop.

---

## Step 1 — Walk the directory tree

From `<repo-path>`, recursively count files by extension. Skip these directories entirely:
`.git/`, `node_modules/`, `target/`, `build/`, `dist/`, `.idea/`, `__pycache__/`, `.venv/`, `venv/`, `env/`, `.env/`, `bin/`, `out/`

Count only source files. Track counts for:
- `.java`, `.kt` → Java/Kotlin
- `.py` → Python
- `.ts`, `.tsx` → TypeScript
- `.js`, `.jsx` → JavaScript
- `.go` → Go
- `.rb` → Ruby
- `.php` → PHP
- `.cs` → C#
- `.cpp`, `.cc`, `.cxx` → C++

---

## Step 2 — Determine significant languages

A language is **significant** if its file count is ≥ 20% of total source files OR ≥ 15 files, whichever is lower.

Examples:
- 100 .java, 5 .py → Java is significant, Python is not (< 15 files and < 20%)
- 150 .py, 80 .ts → both significant (polyglot)
- 200 .java, 20 .py → both significant (20 .py ≥ 15 threshold)

List all significant languages in descending file count order. The first is `primary_language`.

---

## Step 3 — Detect frameworks from config files

Look for these files at the repo root and common subdirectories:

**Java/Kotlin:**
- `pom.xml` → Maven; check `<dependencies>` for:
  - `spring-boot-starter` → `spring-boot`
  - `spring-webmvc` → `spring-mvc`
  - `struts2-core` → `struts`
  - `jakarta.ws.rs` or `javax.ws.rs` → `jax-rs`
- `build.gradle` or `build.gradle.kts` → Gradle; same dependency checks

**Python:**
- `requirements.txt` or `requirements/*.txt` → check for:
  - `fastapi` → `fastapi`
  - `flask` → `flask`
  - `django` → `django`
  - `starlette` → `starlette`
- `pyproject.toml` → same checks under `[project.dependencies]` or `[tool.poetry.dependencies]`
- `setup.py` → same checks

**TypeScript / JavaScript:**
- `package.json` → check `dependencies` and `devDependencies` for:
  - `next` → `nextjs`
  - `react` (without `next`) → `react`
  - `express` → `express`
  - `fastify` → `fastify`
  - `vue` → `vue`
  - `angular` → `angular`
  - `svelte` → `svelte`

**Go:**
- `go.mod` → check `require` block for:
  - `gin-gonic/gin` → `gin`
  - `gorilla/mux` → `gorilla-mux`
  - `labstack/echo` → `echo`
  - `gofiber/fiber` → `fiber`

If no framework detected for a language, set `"unknown"`.

---

## Step 4 — Determine pipeline skills to run

Map each significant language to its SAST skills:

| Language | Crawl skill | Find-vulns skill |
|---|---|---|
| Java or Kotlin | `crawl-java` | `find-vulns-java` |
| Python | `crawl-python` | `find-vulns-python` |
| TypeScript or JavaScript | `crawl-typescript` | `find-vulns-typescript` |
| Go | `crawl-java` (generic fallback) | `find-vulns-java` (generic fallback) |
| Other | `crawl-java` (generic fallback) | `find-vulns-java` (generic fallback) |

For fallback languages (Go, Ruby, C#, etc.), note in `warnings[]` that no dedicated skill exists and results will be partial.

If a repo has BOTH Python and TypeScript (common pattern: Python backend + React frontend), include both in the pipeline arrays — the orchestrator will run them sequentially and merge outputs.

---

## Step 5 — Write language-manifest.json

Write to `language-manifest.json` in the **current working directory** (not inside the repo). Overwrite if exists.

```json
{
  "repo_path": "<absolute path to repo>",
  "detected_at": "<ISO 8601 timestamp>",
  "file_counts": {
    ".java": 0,
    ".py": 0,
    ".ts": 0,
    ".tsx": 0,
    ".js": 0
  },
  "languages": ["python", "typescript"],
  "primary_language": "python",
  "polyglot": true,
  "frameworks": {
    "python": "fastapi",
    "typescript": "react"
  },
  "config_files_found": ["requirements.txt", "package.json"],
  "pipeline": {
    "crawl": ["crawl-python", "crawl-typescript"],
    "find_vulns": ["find-vulns-python", "find-vulns-typescript"]
  },
  "warnings": []
}
```

---

## Constraints

- Do NOT read source files — only count file extensions and read config files (pom.xml, requirements.txt, package.json, go.mod, pyproject.toml)
- If `<repo-path>` does not exist, print an error and stop
- If no significant language is found (empty repo, docs-only, etc.), set `primary_language: "unknown"` and `pipeline: { crawl: [], find_vulns: [] }` and note in warnings

---

## Completion

```
detect-language complete.
  Repo          : <repo-path>
  Languages     : <comma-separated significant languages>
  Primary       : <primary_language> (<framework>)
  Polyglot      : <yes/no>
  Pipeline      : crawl: <skills> | find-vulns: <skills>
  Output        : language-manifest.json
```
