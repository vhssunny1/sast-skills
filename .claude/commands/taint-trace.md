Perform cross-file taint analysis on findings from find-vulns. For each finding, trace the full source-to-sink data flow across file and method boundaries. Confirm, deny, or enrich each finding with a verified taint path.

This agent operates AFTER find-vulns. It does NOT re-scan for new vulnerabilities. It asks: "Can I follow the attacker's data from where it enters the application all the way to the dangerous operation, crossing file boundaries?"

## Input

`$ARGUMENTS` format: `[--findings <path>] [--crawl <path>]`

- `--findings <path>` — path to `findings.json` (default: `./findings.json`)
- `--crawl <path>` — path to `crawl-output.json` (default: `./crawl-output.json`)

## Step 1 — Load inputs

Read both files:
- `findings.json` — the candidate findings from find-vulns
- `crawl-output.json` — the file map (roles, entry points, routes)

Extract from crawl-output.json:
- `repo_path` — needed to read source files
- `files[]` — the full file list with roles, used to build the call graph
- `entry_points[]` — controllers and their routes, used as taint entry nodes
- `framework` — affects how user input enters the app

If either file is missing, print an error and stop.

## Step 2 — Understand what you are doing

Before touching any finding, internalize this mental model:

### The call graph for a typical Java web app looks like this:

```
HTTP Request
    ↓
[Entry Point — Controller / Action]     ← user data enters here (HTTP params, cookies, headers)
    ↓  calls
[Service Layer]                          ← business logic; may transform, validate, or pass data through
    ↓  calls
[DAO / Repository Layer]                 ← data access; dangerous sinks often live here (queries)
    ↓
[Database / OS / Output]                 ← the actual sink (query executes, command runs, HTML rendered)
```

Your job is to walk this graph for each finding — upward from sink to source — and verify that tainted data actually flows through each hop without being sanitized.

### Taint propagation rules

Taint travels FORWARD (source → sink). You trace it BACKWARD (sink → source) to verify the path exists.

**Taint propagates through:**
- Method arguments — if a tainted value is passed as an argument, the parameter in the called method is tainted
- Return values — if a method returns a tainted value and the caller uses it, the caller's variable is tainted
- Field assignment — if a tainted value is stored in a field and later read, the field read is tainted
- String concatenation — `"SELECT * FROM " + taintedValue` produces a tainted string
- Collections — adding a tainted value to a list/map taints that element when retrieved

**Taint does NOT propagate through (sanitization breaks the chain):**
- Parameterized query binding — `setParameter("name", taintedValue)` — the DB driver handles escaping
- Strict allowlist validation that REJECTS on mismatch — `if (!value.matches("[a-zA-Z0-9]+")) throw/return`
- HTML encoding at output — `fn:escapeXml(taintedValue)` breaks XSS taint
- Domain allowlist check for redirects that rejects non-matching URLs
- Re-authentication or privilege re-verification from server-side session

**Taint is NOT broken by:**
- Null checks — `if (value != null)` does not remove injection risk
- Logging the value — logging doesn't sanitize it for later use
- Length checks or format checks that still allow dangerous characters (e.g. `length < 100` does not prevent SQL injection)
- Casting — `(int) value` does break numeric injection but not string injection

## Step 3 — Build a lightweight call graph

Before tracing individual findings, build a mental model of the codebase's call structure by reading the entry_point files.

For each entry_point in `crawl-output.json`:
1. Read the file
2. Note which service/DAO methods it calls (look for injected fields and method calls on them)
3. Note how user data flows in (in Struts2: setter fields populated by framework; in Spring: method parameters annotated with `@RequestParam`, `@PathVariable`, etc.)

This gives you a map like:
```
PingAction.execute()
  → calls: doExecCommand()          [same file, receives address via getAddress()]
  → user input enters via: setAddress() populated from HTTP param "address"

UserAction.edit()
  → calls: userService.find(getUserId())
  → calls: userService.save(user)
  → user input enters via: setUserId(), setPassword(), setEmail()

ApiAction.adminShowUsers()
  → calls: userService.findAllUsers()
  → user input enters via: getCookies() on the request
```

You do not need to be exhaustive here — focus on the entry points relevant to the findings you need to trace.

## Step 4 — Trace each finding

For each finding in `findings.json`, perform a taint trace. Work through these steps:

### 4a. Identify the sink location

From the finding:
- `file` — where the dangerous operation is
- `method` — which method contains the sink
- `sink` — what the dangerous operation is
- `source` — what the finding claims carries user-controlled data

### 4b. Trace backward from the sink

**If the sink is in an entry_point file (controller):**
- The source is likely a field set by the framework (Struts2 setter, Spring `@RequestParam`)
- Read the file if not already read
- Verify: is the field with the tainted name actually used at the sink with no sanitization between the setter and the sink?
- This is usually a single-file trace — confirm or deny in that one file

**If the sink is in a service or DAO file:**
- The source enters the app at an entry_point, passes through to the service/DAO
- Read the calling entry_point file(s) — look for which entry_point(s) call the method containing the sink
- To find callers: search the entry_point files you already read for calls to the method name identified in the finding
- Verify: at each hop (entry_point → service → DAO), is the tainted value passed through as-is? Or is it sanitized or transformed?

**If the sink is in a JSP file:**
- The source is a request parameter or an action field
- JSP output sinks are short paths — the tainted value usually comes directly from `request.getParameter()` or from an action field populated by the framework
- Confirm by reading the JSP and verifying the output expression uses a value that is request-derived and not encoded

### 4c. Read intermediate files as needed

For each hop in the call chain that you have not yet read:
1. Read the file
2. Find the specific method involved in the chain
3. Answer: does the tainted value arrive as a parameter? Is it stored in a field or passed directly? Is anything done to it that removes taint? Is it passed to the next hop unchanged?

**Do not read the entire codebase.** Only read files you need to verify or deny the taint path for the finding at hand. In a well-structured Java app, most taint paths involve 2–4 files.

### 4d. Determine the outcome

After reading all relevant files:

**CONFIRMED** — You can trace the tainted value from its entry point through each intermediate hop to the sink, with no effective sanitization at any step.
- Set `taint_confirmed: true`
- Set `confidence_after_trace` to 0.90–1.00
- Record the full path in `taint_path[]`

**DENIED** — You found effective sanitization at one or more hops, or the tainted value does not actually reach the sink you would expect.
- Set `taint_confirmed: false`
- Set `confidence_after_trace` to 0.10–0.30
- Record where sanitization was found in `taint_path[]` with a note
- This finding is likely a false positive — the validator will handle it

**PARTIAL** — You can see part of the path but cannot fully verify one hop (e.g. the caller passes through a layer you could not fully read, or the method is inherited).
- Set `taint_confirmed: null`
- Set `confidence_after_trace` to 0.50–0.69
- Record what you could and could not verify

**UNREACHABLE** — The sink file's method is never called from any entry_point in the codebase (dead code, internal utility, test helper).
- Set `taint_confirmed: false`
- Set `confidence_after_trace` to 0.05
- Note: "method appears unreachable from any mapped entry point"

## Step 5 — Write enriched findings

Update `findings.json` in place. For each finding, add these fields:

```json
{
  "taint_confirmed": true,
  "confidence_after_trace": 0.97,
  "taint_path": [
    {
      "step": 1,
      "file": "src/main/java/com/appsecco/dvja/controllers/PingAction.java",
      "method": "execute",
      "role": "entry_point",
      "note": "HTTP param 'address' auto-populated into address field via setAddress() by Struts2; no validation present"
    },
    {
      "step": 2,
      "file": "src/main/java/com/appsecco/dvja/controllers/PingAction.java",
      "method": "doExecCommand",
      "role": "entry_point",
      "note": "getAddress() called; value concatenated directly into shell command array element; Runtime.exec() called"
    }
  ],
  "sanitization_gaps": [
    "No input validation between HTTP param and Runtime.exec()",
    "Address value not checked against IP address regex or allowlist"
  ]
}
```

**`taint_path[]` rules:**
- Each step must name a real file and real method you actually read
- The `note` must describe what happens to the tainted value at that step
- Steps must be in order from entry point (step 1) to sink (last step)
- If the sink and entry point are in the same file/method, the path has one step

**`sanitization_gaps[]`:** List specifically what sanitization is ABSENT that would have broken the chain. This is useful for fix generation.

## Step 6 — Write the output

Overwrite `findings.json` with the enriched version. Every finding must have the `taint_confirmed`, `confidence_after_trace`, `taint_path`, and `sanitization_gaps` fields added. Findings that could not be traced get `taint_confirmed: null` and an explanation in the path.

Also add a top-level `taint_summary` to `findings.json`:

```json
{
  "taint_summary": {
    "traced": 10,
    "confirmed": 7,
    "denied": 2,
    "partial": 1,
    "unreachable": 0,
    "additional_files_read": 5
  }
}
```

## Constraints

- Do NOT add new findings. Only enrich existing ones.
- Do NOT re-read files that find-vulns already analyzed unless you need them for a specific cross-file hop.
- Read files on demand, per finding — do not read the whole codebase upfront.
- Every field in `taint_path[]` must refer to a file and method you actually read during this trace.
- If you cannot trace a finding, say so explicitly — do not fabricate a path.

## Downstream consumers

- `/validate-findings` uses `taint_confirmed` and `confidence_after_trace` to score and filter findings
- `/scan-report` uses `taint_path` to render call chain evidence in the report
- `/generate-fix` uses `sanitization_gaps` to know exactly what fix to apply

## Completion

```
taint-trace complete.
  Findings traced  : <N>
  Confirmed        : <N> (full source-to-sink path verified)
  Denied           : <N> (sanitization found — likely false positive)
  Partial          : <N> (path incomplete — needs manual review)
  Files read       : <N> additional files
  Output           : findings.json (enriched in place)
```
