Hunt a codebase for path traversal, directory traversal, and zip slip vulnerabilities — from user-controlled filenames and paths through file system operations. Trace every user-supplied path component to its file system use. Write structured findings to pathtrav-findings.json.

Do NOT flag every `open(path)` call. The path must trace to attacker-controlled input without proper canonicalization and boundary enforcement. Reason about what files the attacker can read, write, or execute.

## Background: Why This Skill Exists

Novee found path traversal in a collaboration feature — a surface that was heavily used but under-audited. Path traversal bugs are consistently underestimated because developers add partial mitigations (`replace("../", "")`) that are trivially bypassed. This skill looks for the full class, including zip slip, null byte injection, and encoding bypass.

## Input

`$ARGUMENTS` format: `[--repo <path>] [--lang <python|go|java|node>]`

- `--repo <path>` — repo root (default: current directory)
- `--lang <name>` — auto-detected if omitted

## Step 1 — Map File System Sinks

Glob for file operation sinks by language:

**Python:** `open(`, `os.open(`, `os.path.join(`, `pathlib.Path(`, `shutil.copy`, `shutil.move`, `os.makedirs`, `os.remove`, `os.rename`, `os.listdir`, `glob.glob(`
**Go:** `os.Open`, `os.Create`, `ioutil.ReadFile`, `filepath.Join`, `os.Stat`, `os.Remove`
**Java:** `new File(`, `Files.readAllBytes`, `FileInputStream`, `FileOutputStream`, `Paths.get(`
**Node:** `fs.readFile`, `fs.writeFile`, `fs.createReadStream`, `path.join(`, `path.resolve(`
**General:** File serving endpoints, static file handlers, template loaders

Also glob for archive handling: `zipfile.ZipFile`, `tarfile.open`, `ZipInputStream`, `TarArchiveInputStream`, `unzip`, `tar`, `jar`

## Step 2 — The 5 Path Traversal Classes

---

### Class 1 — Classic Path Traversal (CWE-22)

User-supplied path component used in a file operation without canonicalization.

**Pattern:**
```python
file_path = os.path.join(BASE_DIR, user_filename)
with open(file_path) as f:
    return f.read()
```
If `user_filename` is `../../etc/passwd`, the join resolves outside `BASE_DIR`.

**SOURCES (attacker-controlled):**
- Filename from HTTP request: `?file=`, `?path=`, `?name=`, `?template=`, `?page=`
- Filename from multipart upload (the `filename` field in Content-Disposition)
- Path segments from URL routing: `/files/{filename}`, `/templates/{name}`
- Values from user-controlled JSON/form body fields named `path`, `file`, `filename`, `resource`
- Filenames extracted from archive contents (zip slip — see Class 3)

**SINKS:**
- `open(path)` — file read/write
- `os.path.join(base, user_input)` — path construction (only safe if followed by `realpath` + boundary check)
- `send_file(path)` — Flask/Django file serving
- Template loader: `render_template(user_input)` — path traversal to load arbitrary templates

**Sanitization (genuine):**
```python
safe_path = os.path.realpath(os.path.join(BASE_DIR, user_input))
if not safe_path.startswith(os.path.realpath(BASE_DIR) + os.sep):
    raise PermissionError()
```
Both `realpath` (resolves `..` and symlinks) AND boundary check are required.

**Sanitization (insufficient — all bypassable):**
- `user_input.replace("../", "")` — bypassed by `....//` → after replace → `../`
- `user_input.replace("..", "")` — bypassed by `..../...//`
- `if ".." in user_input: reject` — bypassed with URL encoding: `%2e%2e%2f`
- `os.path.basename(user_input)` — strips directory components but misses symlinks
- Checking `user_input.startswith("/")` — `../` doesn't start with `/` but still traverses

**For each file operation with user input in the path:**
1. Is `realpath` or `abspath` called to resolve `..` BEFORE the boundary check?
2. Is there a boundary check (`startswith(BASE_DIR)`) AFTER canonicalization?
3. Does the check use `BASE_DIR + os.sep` to prevent prefix bypass (`/base_dirabc` passing a `/base_dir` check)?
4. Could URL-encoded `%2e%2e%2f` or double-encoded `%252e%252e%252f` bypass the check?

---

### Class 2 — File Upload Filename Injection (CWE-22 via upload)

Uploaded file is saved using the attacker-controlled `filename` from the HTTP request.

**Pattern:**
```python
filename = request.files["file"].filename
save_path = os.path.join(UPLOAD_DIR, filename)
request.files["file"].save(save_path)
```

**Attack:** Upload a file named `../../../../etc/cron.d/backdoor` → writes to cron directory.

**Secondary attack:** Upload a file named `shell.php` to a web-accessible directory → remote code execution.

**Sanitization (genuine):**
- `werkzeug.utils.secure_filename(filename)` — strips path separators, keeps only safe characters
- Storing files with server-generated UUIDs instead of user-supplied names
- Writing to a non-web-accessible directory

**Sanitization (insufficient):**
- Only checking `os.path.basename(filename)` — Windows path separators (`\`) may still traverse on Linux
- Removing only `/` but not `\` or URL-encoded variants
- Keeping original extension without allowlisting: saves `.php`, `.jsp`, `.py` to web root

**For each file upload handler:**
1. Is the filename from the upload request sanitized with `secure_filename` or equivalent?
2. Is the save directory outside the web root?
3. Is file extension validated against an allowlist?

---

### Class 3 — Zip Slip (CWE-22 via archive extraction)

Archive contains entries with path traversal sequences in their names.

**Pattern:**
```python
with zipfile.ZipFile(uploaded_zip) as zf:
    zf.extractall(EXTRACT_DIR)
```
If the ZIP contains an entry named `../../etc/cron.d/backdoor`, it extracts outside `EXTRACT_DIR`.

**Python:** `zipfile.extractall()`, `tarfile.extractall()` — both vulnerable by default
**Java:** `ZipInputStream.getNextEntry().getName()` used directly in file path
**Go:** `archive/zip.File.Name` used directly in path construction
**Node:** `unzipper`, `adm-zip`, `node-tar` — varies by library

**Sanitization (genuine):**
Manually iterating entries and checking each path:
```python
for entry in zf.namelist():
    entry_path = os.path.realpath(os.path.join(EXTRACT_DIR, entry))
    if not entry_path.startswith(os.path.realpath(EXTRACT_DIR) + os.sep):
        raise Exception("Zip slip detected")
    zf.extract(entry, EXTRACT_DIR)
```

**For each archive extraction:**
1. Is `extractall()` called directly without validating entry names? Finding.
2. If entries are validated: is each entry path canonicalized with `realpath` before boundary check?
3. Does the check cover both `/` and `\` separators and URL-encoded variants?

---

### Class 4 — Null Byte Injection (CWE-626)

In some languages/runtimes, a null byte (`\x00`, `%00`) in a filename terminates the string at the C level, truncating what follows.

**Pattern:**
```
GET /files/config.php%00.jpg
```
Server checks extension `.jpg`, but C runtime opens `config.php`.

**Relevant contexts:**
- PHP (older versions) — `fopen`, `file_get_contents` with null byte
- Python (before 3.x) — `open()` could be affected in some builds
- Java — `new File(path)` was vulnerable in some JVM versions
- C extensions called from Python/Node

**Sanitization:** Rejecting any input containing `\x00` or `%00`.

**For each file operation with user input:**
1. Is the input checked for null bytes before use?
2. Does the framework/language version have known null byte vulnerability?

---

### Class 5 — Template / Resource Loader Traversal (CWE-22 via include)

Template engines and resource loaders that accept user-supplied names can load arbitrary files.

**Pattern:**
```python
return render_template(request.args.get("page") + ".html")
# With ?page=../../../../etc/passwd%00
```

**Also:**
- `include(user_input)` in PHP
- Dynamic class/module loading: `importlib.import_module(user_input)` in Python
- `require(user_input)` in Node

**Sanitization (genuine):**
- Template name from a fixed allowlist only
- Base directory enforced with `realpath` check

**For each dynamic template/resource load:**
1. Is the template name from user input?
2. Is it validated against a fixed allowlist?
3. Is it restricted to a specific directory with `realpath` boundary check?

---

## Step 3 — Build the Scan Queue

Priority order:
1. File upload handlers
2. File serving endpoints
3. Archive extraction code
4. `os.path.join` / `path.join` / `filepath.Join` with non-hardcoded second argument
5. Template loaders with dynamic names
6. Collaboration features (shared document editing, import/export)

## Step 4 — Analyze Each File

Read the full file. Apply relevant class analysis.

**For each path construction:**
> Q1: Trace both arguments to `os.path.join` — which ones are user-controlled?
> Q2: Is `realpath`/`abspath` called before the boundary check?
> Q3: Is the boundary check done with `startswith(base + sep)` not just `startswith(base)`?
> Q4: Are `\`, URL-encoded `%2f`, double-encoded `%252f`, and null bytes `%00` handled?

**For archive extraction:**
> Q1: Is `extractall()` called directly? Or are entry names individually validated?

## Step 5 — Score and Filter

**Confidence:**
- **0.90–1.00** — User input directly in path without `realpath` + boundary check
- **0.70–0.89** — Partial mitigation present but bypassable (`replace("../","")`, `basename()`)
- **0.50–0.69** — Traversal through multiple function hops; may be mitigated elsewhere
- **< 0.50** — Discard

**Number:** `PT-001`, `PT-002`, ...

**Severity:**

| Severity | Criteria |
|---|---|
| Critical | Write to arbitrary path (RCE via cron/webshell); read of `/etc/passwd`, private keys |
| High | Zip slip to web root; read of application config, session secrets |
| Medium | Read of files outside upload directory but not sensitive system files |
| Low | Template traversal limited by file extension; null byte only on older platforms |

## Step 6 — Write pathtrav-findings.json

```json
{
  "scanned_at": "<ISO 8601 timestamp>",
  "repo_path": "<absolute path>",
  "total_findings": 0,
  "findings_by_severity": { "critical": 0, "high": 0, "medium": 0, "low": 0 },
  "findings": [
    {
      "id": "PT-001",
      "class": "path-traversal | upload-filename | zip-slip | null-byte | template-traversal",
      "cwe": "CWE-22",
      "severity": "high | critical | medium | low",
      "confidence": 0.92,
      "confidence_note": "",
      "file": "app/views/collaboration.py",
      "line": 88,
      "function": "save_document",
      "source": "filename — from request.form['filename'], user-controlled",
      "sink": "open(os.path.join(DOCS_DIR, filename), 'w')",
      "sanitization_present": "filename.replace('../', '') — bypassed by '....//....//etc/passwd'",
      "bypass_payload": "....//....//etc/passwd",
      "target_files": "/etc/passwd, application .env, private keys in ~/.ssh/",
      "description": "The document filename is sanitized by removing '../' substrings, but this is bypassed by '....//'. The resulting path escapes DOCS_DIR.",
      "fix_hint": "Use realpath() then check startswith(os.path.realpath(DOCS_DIR) + os.sep). Never use string replacement to sanitize paths."
    }
  ],
  "skipped_files": [],
  "warnings": []
}
```

## Hard Rules

- Do not flag `os.path.join` calls where all arguments are hardcoded or come from trusted server-side config.
- `bypass_payload` must be a concrete example that bypasses the specific mitigation present — not just `../`.
- `target_files` must name realistic high-value files for this application type.
- Do not flag `open()` calls inside test files or scripts that clearly run with trusted input.

## Completion

```
path-traversal complete.
  Repo          : <repo_path>
  Lang          : <language>
  Files scanned : <N>
  Findings      : <total> (<critical> critical / <high> high / <medium> medium / <low> low)
  Output        : pathtrav-findings.json
```
