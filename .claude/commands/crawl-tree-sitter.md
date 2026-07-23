Parse every source file in the repository using tree-sitter to produce an enriched `crawl-output.json` with exact AST data. Replaces the heuristic 120-line role detection used by crawl-python/crawl-typescript/crawl-java. Runs after detect-language and before joern-parse — Joern consumes the exact entry-point signatures and user-input source parameters this skill extracts.

When tree-sitter is available, the language-specific crawl skills in Group 1 are skipped. When it is not installed, the pipeline falls back to the standard crawl skills transparently.

## Input

`$ARGUMENTS` format: `<repo-path> --manifest language-manifest.json [--out <path>] [--ts-bin <path>]`

- `<repo-path>` — required. Absolute path to the repository root.
- `--manifest <path>` — path to `language-manifest.json` (default: `./language-manifest.json`)
- `--out <path>` — output path (default: `./crawl-output.json`)
- `--ts-bin <path>` — path to tree-sitter CLI binary (default: auto-detect)

---

## Step 1 — Detect tree-sitter installation

Check for the tree-sitter CLI in this order:

1. `$TREE_SITTER_HOME/bin/tree-sitter` if `$TREE_SITTER_HOME` is set
2. `tree-sitter` on `$PATH` (run `tree-sitter --version`)
3. Value of `--ts-bin` flag

If tree-sitter CLI is not found:

```
crawl-tree-sitter: tree-sitter CLI not installed — AST crawl skipped.
  Install: https://tree-sitter.github.io/tree-sitter/using-parsers#installation
  Effect : pipeline falls back to heuristic crawl-python/crawl-typescript/crawl-java skills.
  To suppress: pass --skip-tree-sitter to sast-full-scan.
```

Write a stub `crawl-output.json`:
```json
{ "ts_available": false, "reason": "tree_sitter_not_installed" }
```
Stop — do not error. sast-full-scan detects the stub and runs standard crawl skills.

---

## Step 2 — Determine scope from language-manifest

Read `language-manifest.json`. Extract `languages[]` and `repo_path`.

Map languages to tree-sitter grammars and file extensions:

| Language | Grammar package | Extensions |
|---|---|---|
| `typescript` or `javascript` | `tree-sitter-javascript` | `.ts`, `.tsx`, `.js`, `.jsx` |
| `python` | `tree-sitter-python` | `.py` |
| `java` or `kotlin` | `tree-sitter-java` | `.java`, `.kt` |

For any language without a grammar mapping, note it in `warnings[]` and skip — the standard crawl skill for that language will run as a fallback during Group 1.

---

## Step 3 — Collect files

Walk `<repo-path>` recursively. Collect files by extension per language scope from Step 2.

Exclude these directories entirely:
`.git/`, `node_modules/`, `dist/`, `build/`, `.next/`, `coverage/`, `.cache/`, `out/`, `target/`, `__pycache__/`, `.venv/`, `venv/`, `env/`, `.idea/`

Exclude test files (unless explicitly included):
- Files under `__tests__/`, `test/`, `tests/`, `spec/`
- Files ending in `.test.ts`, `.spec.ts`, `.test.py`, `_test.py`, `Test.java`

Skip files exceeding 5000 lines — add to `skipped_files` with reason `exceeds line limit`.

---

## Step 4 — Parse each file with tree-sitter

For each collected file, run:

```bash
tree-sitter parse --json <file-path>
```

This outputs the full AST as a JSON tree. Parse the output and extract the fields described below.

If `tree-sitter parse` fails for a file (syntax error, unsupported dialect):
- Add to `skipped_files` with reason `parse_error: <stderr>`
- Continue to the next file — do not abort

**What to extract from the AST (per language):**

### TypeScript / JavaScript AST extraction

Traverse the AST JSON. Collect nodes of these types:

**Function and route definitions:**
- `function_declaration`, `arrow_function`, `function_expression` — name, line, parameter names, whether async, whether exported
- `call_expression` where callee matches `app.get|app.post|app.put|app.delete|app.patch|app.use|router.get|router.post|router.put|router.delete|router.patch|router.use` — extract HTTP method, path string argument, handler name
- `decorator` nodes with names in `Get|Post|Put|Delete|Patch|Controller|UseGuards|Injectable` — NestJS/TypeDI patterns

**Imports and exports:**
- `import_declaration` — extract `source` value and imported names/namespace
- `export_declaration`, `export_default_declaration` — note what is exported

**User-input sources (exact AST — anywhere in file):**
- `member_expression` chains matching `req.body.*`, `req.query.*`, `req.params.*`, `req.headers.*`, `req.cookies.*` — extract the field name accessed
- `call_expression` where callee is `useParams`, `useSearchParams`, `useLocation` — note destructured field names from the result
- `member_expression` where object is `document` and property is `URL`, `referrer`, `cookie`, or object is `window.location` and property is `href`, `search`, `hash`
- `call_expression` where callee is `document.getElementById` / `querySelector` followed by `.value` access

**Dangerous patterns (exact AST — anywhere in file):**
- `assignment_expression` where left side is `*.innerHTML` or `*.outerHTML` — record line and right-hand code snippet
- `jsx_attribute` where name is `dangerouslySetInnerHTML` — record line
- `call_expression` where callee name is `eval` or callee is `new Function(...)` — record line
- `call_expression` where callee chain is `child_process.exec|spawn|execFile|execSync|spawnSync` — record line
- `call_expression` where callee is `fs.readFile|readFileSync|writeFile|writeFileSync|createReadStream|sendFile` with a non-constant first argument — record line
- Template literal (`template_string`) containing SQL keywords (`SELECT`, `INSERT`, `UPDATE`, `DELETE`) with embedded `${...}` substitutions — record line
- `call_expression` where callee is `fetch|axios.get|axios.post|got|request` with a dynamic (non-string-literal) first argument — record line

**React/JSX:**
- `jsx_element` presence — marks file as having UI rendering
- `jsx_attribute` where name is `onClick`, `onChange`, `onSubmit` — marks file as handling user interaction

### Python AST extraction

**Function and route definitions:**
- `function_definition` nodes — name, line, parameter names (including type annotations), whether async, whether decorated
- `decorated_definition` where the decorator is a `call` with attribute in `route|get|post|put|delete|patch` (Flask/FastAPI patterns) — extract HTTP method and path string
- `class_definition` — class name, base classes, line

**Imports:**
- `import_statement` — module name
- `import_from_statement` — from module, imported names

**User-input sources:**
- `attribute` access on `request` object: `request.form`, `request.args`, `request.json`, `request.data`, `request.headers`, `request.cookies`, `request.get_json()` — record field names accessed
- `parameter` with annotation `Query(...)`, `Path(...)`, `Body(...)`, `Header(...)`, `Cookie(...)` (FastAPI) — record parameter name and annotation type
- `call_expression` to `request.get(...)` — record the key argument

**Dangerous patterns:**
- `call` where function is `eval` or `exec` (not `subprocess.run` — separate check below) — record line
- `call` where function is `os.system`, `os.popen`, `subprocess.run`, `subprocess.call`, `subprocess.Popen`, `subprocess.check_output` with a non-constant first argument — record line
- `call` where function attribute is `execute` or `executemany` on a cursor/connection object, where the argument contains string formatting (`%`, `.format()`, f-string) — SQL injection risk; record line
- `call` where function is `open(` with a non-constant filename argument — record line
- `call` where function is `yaml.load` without `Loader=yaml.SafeLoader` — deserialization risk; record line
- `call` where function is `pickle.loads` or `marshal.loads` — deserialization risk; record line

### Java AST extraction

**Class and method definitions:**
- `class_declaration` — class name, superclass, interfaces implemented, line
- `method_declaration` — method name, return type, parameters (name + type), annotations, line

**Annotations (Spring / Struts2):**
- `annotation` nodes with names in `GetMapping|PostMapping|PutMapping|DeleteMapping|RequestMapping|Controller|RestController|Service|Repository|Component|Autowired|PathVariable|RequestParam|RequestBody|RequestHeader|SessionAttribute` — record annotation name and arguments
- `annotation` with names in `Action` (Struts2) — record class as entry_point

**User-input sources:**
- `formal_parameter` with annotation `@RequestParam`, `@PathVariable`, `@RequestBody`, `@RequestHeader`, `@CookieValue` — extract parameter name and type
- Method named `set*` in a class extending `ActionSupport` or implementing `Action` — Struts2 setter injection pattern; extract property name from method name suffix
- `method_invocation` on `HttpServletRequest` object: `getParameter`, `getHeader`, `getCookies`, `getInputStream`, `getReader` — record method name and string argument

**Dangerous patterns:**
- `method_invocation` where name is `executeQuery|executeUpdate|execute` with a string argument built by concatenation (`+`) — SQL injection; record line
- `class_instance_creation` where type is `ProcessBuilder` or `Runtime.getRuntime().exec(` — command injection; record line
- `method_invocation` where object type is `Runtime` and method is `exec` — record line
- `method_invocation` where result is used as `ObjectInputStream` input then deserialized — deserialization risk

---

## Step 5 — Classify role from AST

For each file, assign a `role` based on the extracted AST data. Apply the FIRST matching rule:

| Role | AST evidence |
|---|---|
| `entry_point` | Has route registrations (app.get/router.post/etc.) OR has Spring @*Mapping annotations OR has Flask/FastAPI route decorators OR is in `pages/`, `app/` directory (Next.js) OR has Struts2 @Action annotation |
| `middleware` | Exports a function with exactly 3 parameters named `(req, res, next)` OR has `app.use(` call at module level OR class name contains `Middleware|Filter|Interceptor` OR has Spring `@Component` implementing `HandlerInterceptor` |
| `service` | Has Spring `@Service` annotation OR class name ends in `Service` OR imports an ORM/HTTP client AND has public methods returning data |
| `dao` | Has Spring `@Repository` annotation OR class name ends in `Repository|DAO|Dao` OR directly invokes `executeQuery|executeUpdate|findBy*|save|delete` on an ORM object |
| `model` | Only contains `interface`, `type`, `class` with no methods (only field declarations), or Java POJO with only getters/setters |
| `component` | Has JSX elements in render output AND no route registration |
| `config` | Only constants/exports, no function bodies beyond simple assignments, OR file name matches `*.config.*|constants.*|settings.*|config.*` |
| `util` | Everything else |

---

## Step 6 — Compute security_priority from AST

For each file, score `security_priority` (1–5) based on dangerous patterns found anywhere in the file:

| Score | Conditions |
|---|---|
| 5 | Has `eval`/`exec` call OR SQL template literal with substitution OR `innerHTML` assignment OR `dangerouslySetInnerHTML` OR `Runtime.exec` OR `child_process.exec|spawn` OR deserialization call (pickle.loads, ObjectInputStream) |
| 4 | Has `fetch`/`axios` with dynamic URL OR `fs.readFile|readFileSync` with dynamic path OR `res.redirect`/`router.push` with dynamic value OR `executeQuery` with concatenation |
| 3 | Has user-input sources (`req.body|req.query`, `request.form|args`, `@RequestParam|@PathVariable`) anywhere in file OR handles form `onChange|onSubmit` events |
| 2 | Imports from a security_priority ≥ 3 file in this repo OR has `role: "entry_point"` or `role: "middleware"` without dangerous patterns |
| 1 | Pure model/type/constant — no function logic, no user input, no external calls |

If multiple conditions apply, use the highest score.

---

## Step 7 — Write enriched crawl-output.json

Write to `--out` path (default: `./crawl-output.json`). Schema extends the standard crawl-output.json with AST fields:

```json
{
  "repo_path": "<absolute path>",
  "scanned_at": "<ISO 8601>",
  "ts_available": true,
  "ts_version": "<tree-sitter --version output>",
  "language": "typescript",
  "languages_detected": ["typescript"],
  "framework": "express",
  "total_files": 0,
  "entry_points": [
    {
      "path": "routes/login.ts",
      "role": "entry_point",
      "security_priority": 5,
      "routes": [
        { "method": "POST", "path": "/login", "handler": "loginHandler", "line": 10 }
      ],
      "user_input_sources": [
        { "type": "req.body", "field": "email", "line": 15 },
        { "type": "req.body", "field": "password", "line": 16 }
      ]
    }
  ],
  "files": [
    {
      "path": "routes/login.ts",
      "role": "entry_point",
      "lines": 234,
      "language": "typescript",
      "security_priority": 5,
      "ts_enriched": true,
      "ast": {
        "functions": [
          {
            "name": "loginHandler",
            "line": 12,
            "params": ["req", "res"],
            "is_async": true,
            "exported": true
          }
        ],
        "imports": [
          { "source": "express", "names": ["Router"] },
          { "source": "../lib/sequelize", "names": ["sequelize"] }
        ],
        "routes": [
          { "method": "POST", "path": "/login", "handler": "loginHandler", "line": 10 }
        ],
        "user_input_sources": [
          { "type": "req.body", "field": "email", "line": 15 },
          { "type": "req.body", "field": "password", "line": 16 }
        ],
        "dangerous_patterns": [
          {
            "type": "sql_template_literal",
            "line": 45,
            "snippet": "SELECT * FROM users WHERE email = '${email}'"
          }
        ],
        "calls_to": ["sequelize.query", "bcrypt.compare", "jwt.sign"]
      }
    }
  ],
  "security_priority_distribution": {
    "5": 12,
    "4": 18,
    "3": 34,
    "2": 56,
    "1": 89
  },
  "dangerous_pattern_summary": {
    "sql_template_literal": 3,
    "eval": 1,
    "innerHTML_assignment": 5,
    "dynamic_fetch": 8,
    "command_injection": 2,
    "deserialization": 0
  },
  "skipped_files": [],
  "warnings": []
}
```

**Key difference from heuristic crawl:** The `ast` object on each file gives downstream skills (Joern, find-vulns) exact data they previously had to infer:
- `user_input_sources[]` — Joern uses these as precise taint source parameter hints
- `dangerous_patterns[]` — find-vulns uses these to know which sink types exist in which files (no discovery needed for known patterns)
- `routes[]` — exact HTTP method + path for every route handler (no regex guessing from 120 lines)

---

## Step 8 — Print summary

```
crawl-tree-sitter complete.
  Repo       : <repo-path>
  Languages  : <list>
  Files parsed: <N> files (<parse_errors> parse errors)
  Skipped    : <N> (size limit or binary)

  Role distribution:
    entry_point : <N>
    middleware  : <N>
    service     : <N>
    dao         : <N>
    component   : <N>
    util        : <N>

  Security priority:
    Priority 5 (critical sinks)  : <N> files
    Priority 4 (dynamic flows)   : <N> files
    Priority 3 (user input)      : <N> files
    Priority 2 (indirect)        : <N> files
    Priority 1 (no risk signals) : <N> files

  Dangerous patterns found:
    SQL template literals     : <N> locations
    eval / exec calls         : <N> locations
    innerHTML assignments     : <N> locations
    Dynamic fetch URLs        : <N> locations
    Command injection sinks   : <N> locations

  User-input sources mapped:
    req.body / request.form   : <N>
    req.query / request.args  : <N>
    @RequestParam / @PathVar  : <N>
    URL / DOM sources         : <N>

  → Joern will use <N> exact entry-point parameters as taint source hints.
  → find-vulns will use <N> pre-mapped dangerous patterns (skip discovery for these locations).
  Output: crawl-output.json
```

---

## Constraints

- Do NOT read files for semantic analysis — only run `tree-sitter parse --json` and traverse the resulting AST JSON. The LLM does not interpret code logic here; it traverses a structured tree.
- Role classification comes only from AST node types and structural position — never from filename heuristics alone (that is the old approach this skill replaces).
- `dangerous_patterns[].snippet` must be trimmed to ≤ 120 characters — do not include full lines.
- `user_input_sources[]` must only record patterns that tree-sitter confirms exist at the given line number in the AST — do not infer from filenames.
- If tree-sitter produces no output for a language (grammar not installed), add a warning and fall back gracefully — do NOT write an empty `files[]` array for that language.
- The stub `{ "ts_available": false }` must always be valid JSON so sast-full-scan can parse it without errors.

## Downstream consumers

- `/joern-parse` — reads `entry_points[].user_input_sources[]` to configure taint sources precisely; reads `dangerous_patterns[]` to know which sink types to prioritize in CPG queries
- `/find-vulns-typescript`, `/find-vulns-python`, `/find-vulns-java` — reads `files[].ast.dangerous_patterns[]` to pre-confirm known dangerous patterns without re-discovering them; reads `security_priority` for scan queue ordering
- `/sast-full-scan` — if `ts_available: true`, skips the standard language-specific crawl skills in Group 1
