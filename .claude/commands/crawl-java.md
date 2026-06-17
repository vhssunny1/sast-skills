Map a Java repository for downstream SAST analysis. Classifies Java/JSP/XML files by role, identifies HTTP entry points and routes, and writes crawl-output.json.

Called by sast-full-scan when detect-language identifies Java as a significant language.

## Input

`$ARGUMENTS` format: `<repo-path> [--include-tests]`

- `<repo-path>` — absolute or relative path to the repository root
- `--include-tests` — if omitted, test files are excluded

---

## Step 1 — Collect files

Walk `<repo-path>` recursively. Collect files with extensions:
`.java`, `.jsp`, `.jspx`, `.xml`, `.properties`, `.yml`, `.yaml`

Exclude these directories entirely:
`.git/`, `target/`, `build/`, `out/`, `.idea/`, `.mvn/`

Exclude test files unless `--include-tests` is passed:
- Files under any directory named `test/` or `it/`
- Files ending in `Test.java`, `Tests.java`, `IT.java`, `Spec.java`

If total `.java` count exceeds 300:
- List top 5 directories by file count
- Ask user to confirm or narrow the path before continuing

---

## Step 2 — Classify each Java file by role

Scan the first 100 lines for these markers:

| Role | Markers |
|---|---|
| `entry_point` | `@Controller`, `@RestController`, `@RequestMapping`, `extends HttpServlet`, `@Path` (JAX-RS), `@WebServlet` |
| `service` | `@Service`, `implements *Service`, `@Component` with business logic (not config) |
| `dao` | `@Repository`, `extends JpaRepository`, `extends CrudRepository`, `EntityManager`, `JdbcTemplate`, `NamedParameterJdbcTemplate` |
| `model` | `@Entity`, `@Table`, POJO with only fields + getters/setters, `@MappedSuperclass` |
| `filter_interceptor` | `implements Filter`, `implements HandlerInterceptor`, `extends OncePerRequestFilter`, `implements AuthenticationFilter` |
| `config` | `@Configuration`, `@EnableWebSecurity`, class named `*Config`, `*Configuration`, `SecurityConfig` |
| `util` | Everything else |

---

## Step 3 — Extract routes from entry_point files

For each entry_point file, read the full file and extract:
- HTTP method from annotations: `@GetMapping`, `@PostMapping`, `@PutMapping`, `@DeleteMapping`, `@PatchMapping`, `@RequestMapping(method=...)`
- Route path string from the annotation value
- Java method name immediately below the annotation

For Struts2 actions (`extends ActionSupport` or `@Action`): extract action name and namespace from struts.xml or the class name convention.

For Servlets (`extends HttpServlet`): extract URL pattern from `@WebServlet` annotation or web.xml.

---

## Step 4 — Detect framework and dependencies

Parse `pom.xml` (Maven) or `build.gradle` / `build.gradle.kts` (Gradle):

**Java version:** `<java.version>` in pom.xml or `sourceCompatibility` in build.gradle.

**Framework detection:**
- `spring-boot-starter` in dependencies → `spring-boot`
- `spring-webmvc` (no spring-boot) → `spring-mvc`
- `struts2-core` → `struts`
- `jakarta.ws.rs-api` or `javax.ws.rs-api` → `jax-rs`
- None of the above → `unknown`

**Security-sensitive dependencies to flag:**
`log4j` (any version), `jackson-databind` (check version < 2.13), `commons-collections`, `xstream`, `snakeyaml`, `h2` (in-memory DB exposed), any `*-SNAPSHOT` dependency in a non-dev profile.

---

## Step 5 — Write crawl-output.json

Write to `crawl-output.json` in the current working directory. Overwrite if exists.

```json
{
  "repo_path": "<absolute path>",
  "scanned_at": "<ISO 8601 timestamp>",
  "language": "java",
  "languages_detected": ["java"],
  "runtime_version": "11",
  "framework": "spring-boot",
  "total_files": 0,
  "entry_points": [
    {
      "path": "src/main/java/com/example/UserController.java",
      "role": "entry_point",
      "routes": [
        { "method": "POST", "path": "/user/login", "handler": "login" }
      ]
    }
  ],
  "files": [
    {
      "path": "src/main/java/com/example/UserController.java",
      "role": "entry_point",
      "lines": 120,
      "language": "java"
    }
  ],
  "dependencies": [
    { "name": "spring-boot-starter-web", "version": "2.7.0", "security_sensitive": false },
    { "name": "log4j-core", "version": "2.14.1", "security_sensitive": true }
  ],
  "skipped_files": [],
  "warnings": []
}
```

---

## Constraints

- Skip files exceeding 5000 lines — add to `skipped_files` with reason `exceeds line limit`
- Skip binary files — add to `skipped_files` with reason `binary`
- Role detection reads only the first 100 lines; route extraction reads the full file
- JSP/JSPX files: classify as `entry_point` if they contain `<form` or `request.getParameter`; otherwise `util`

---

## Completion

```
crawl-java complete.
  Repo        : <repo-path>
  Framework   : <framework> (Java <version>)
  Files       : <N> Java + <N> JSP + <N> XML mapped
  Entry points: <N> routes across <N> controller files
  Services    : <N> files
  DAOs        : <N> files
  Flagged deps: <list>
  Output      : crawl-output.json
```
