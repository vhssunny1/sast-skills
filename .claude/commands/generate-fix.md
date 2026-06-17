Generate a secure code fix for a single finding from findings.json. Produce a minimal, surgical patch that eliminates the vulnerability without refactoring unrelated code.

## Input

`$ARGUMENTS` format: `<finding-id> [--findings <path>]`

- `<finding-id>` — required. The finding to fix, e.g. `FINDING-001`
- `--findings <path>` — path to `findings.json` (default: `./findings.json`)

If no finding ID provided, print available finding IDs and stop.

## Step 1 — Load the finding

Read `findings.json`. Find the entry where `id` matches the argument.

If not found, print the available IDs and stop.

Extract:
- `file` — the file to patch
- `line` — line number of the sink
- `method` — method containing the vulnerability
- `cwe` — vulnerability class
- `source` — where tainted data originates
- `sink` — the dangerous operation
- `sanitization_gaps[]` — what is missing (from taint-trace)
- `fix_hint` — the suggested fix direction (from find-vulns)
- `taint_path[]` — the full data flow path (from taint-trace)
- `validation_status` — skip if `likely_fp`

If `validation_status` is `likely_fp`, warn the user and ask for confirmation before proceeding.

## Step 2 — Read the vulnerable file

Read the full source file identified by `file`.

Understand the context around the vulnerable method:
- What does the method do?
- What are its inputs and outputs?
- Are there other methods in the same class that have the same vulnerability pattern?
- What imports are already present that a fix might need?
- What imports would a fix need that are not yet present?

## Step 3 — Design the fix

Apply the minimal fix that eliminates the vulnerability. The fix must:

1. **Be surgical** — change only the lines that introduce the vulnerability. Do not refactor, rename, reformat, or "improve" adjacent code.
2. **Not change behavior** — the fix must preserve the method's correct behavior for legitimate inputs.
3. **Address the root cause** — fix the actual source-to-sink connection, not a symptom.
4. **Follow existing code style** — match indentation, brace placement, variable naming, and library choices already in the file.

### Fix strategies by vulnerability class

**CWE-89 (SQL/JPQL Injection) — string concatenation in queries:**
- Replace string concatenation with named parameters
- Use `.setParameter("name", value)` for JPQL/JPA
- Use `PreparedStatement` with `?` placeholders for raw JDBC
- Do NOT rewrite the whole query or change its logic

**CWE-78 (Command Injection) — user input in shell commands:**
- Add strict allowlist validation before the command is built
- The allowlist must use `matches()` with a pattern that permits ONLY safe characters
- If input fails validation, return an error result — do not proceed
- Do NOT try to escape the input for shell — allowlist + reject is the correct fix

**CWE-79 (XSS) — unencoded output in JSP:**
- Replace `<%= request.getParameter("x") %>` with `<c:out value="${param.x}"/>`
- Replace `<s:property escape="false" value="x"/>` with `<s:property value="x"/>` (default escapes)
- Add JSTL taglib declaration if not present: `<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>`

**CWE-601 (Open Redirect) — user-controlled redirect URL:**
- Add an allowlist of permitted domains/paths before the redirect
- Reject or redirect to a safe default if the URL does not match

**CWE-285 (Client-controlled authorization) — cookie/header-based admin check:**
- Remove the cookie-based check entirely
- Replace with a server-side session check: read the user object from session, check its role field
- The session user must have been set during a verified login flow

**CWE-639 (IDOR) — missing ownership check:**
- After fetching the resource, add a check: `if (!resource.getOwnerId().equals(sessionUser.getId())) { ... return error ... }`
- The check must use the session user's identity, not any user-supplied ID

**CWE-916 (Weak password hash) — MD5/SHA1 for passwords:**
- Replace the hashing call with BCrypt
- Add the BCrypt dependency if not present (note it in the fix)
- Update both the hash-generation and the hash-verification call

**CWE-340 (Predictable reset token) — MD5 of username as token:**
- Replace with `SecureRandom` token generation
- Generate a random byte array, encode as hex or base64
- Store the token server-side with a TTL; do not derive it from the username

**CWE-532 (Sensitive data in logs) — password in log statement:**
- Remove the sensitive value from the log statement
- Keep logging what is safe (username, timestamp, operation) — remove the password/token/key

**CWE-476 (Null dereference) — missing null check after lookup:**
- Add `if (result == null) { ... return error or INPUT ... }` immediately after the lookup call
- The null check must come before any method call on the result

## Step 4 — Write the fix

Produce three outputs:

### Output A — Before/After diff (unified diff format)

```diff
--- a/src/main/java/com/appsecco/dvja/services/UserService.java
+++ b/src/main/java/com/appsecco/dvja/services/UserService.java
@@ -72,7 +72,9 @@
 public User findByLoginUnsafe(String login) {
-    Query query = entityManager.createQuery("SELECT u FROM User u WHERE u.login = '" + login + "'");
+    Query query = entityManager.createQuery("SELECT u FROM User u WHERE u.login = :login")
+            .setParameter("login", login);
     List<User> resultList = query.getResultList();
```

### Output B — Explanation

A short paragraph explaining:
1. What the vulnerability was (in one sentence)
2. What the fix does and why it works
3. Any caveats or follow-up actions needed (e.g. "also check if findByEmail() has the same pattern")

### Output C — Test cases (pseudocode or actual Java)

Two test scenarios the developer should verify:
1. **Regression test** — normal input still works correctly after the fix
2. **Security test** — a malicious input is now rejected or rendered harmless

## Step 5 — Check for sibling vulnerabilities

After writing the fix, scan the rest of the same file for the same vulnerability pattern.

If you find the same issue in other methods of the same file, list them as `related_findings` — do not fix them automatically, but flag them so the developer knows.

## Constraints

- Change the minimum number of lines necessary to fix the vulnerability
- Do not change method signatures, class structure, or imports unless the fix requires it
- Do not add comments explaining what you changed — the diff speaks for itself
- Do not fix multiple findings in one invocation — one finding, one targeted fix
- If the fix requires a new dependency (e.g. BCrypt), note the Maven/Gradle coordinates but do not modify pom.xml automatically — warn the user to add it manually

## Completion

```
generate-fix complete.
  Finding    : <finding-id>
  CWE        : <cwe>
  File       : <file>
  Lines changed: <N>
  Related    : <N sibling vulnerabilities found in same file>
```
