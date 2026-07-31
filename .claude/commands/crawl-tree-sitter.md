Parse every source file in the repository using tree-sitter to produce an enriched `crawl-output.json` with exact AST data. Replaces the heuristic 120-line role detection used by crawl-python/crawl-typescript/crawl-java. Runs after detect-language and before joern-parse — Joern consumes the exact entry-point signatures and user-input source parameters this skill extracts.

When tree-sitter is available, the language-specific crawl skills in Group 1 are skipped. When it is not installed, the pipeline falls back to the standard crawl skills transparently.

**This skill is a deterministic script, not an LLM analysis step.** The extraction logic (AST traversal, role classification, source/sink pattern detection) lives in `harness/scripts/crawl_tree_sitter.py` — a checked-in, tested Python script — rather than being performed by reading AST output and reasoning about it turn-by-turn. This was a deliberate change (see project history): running the same "purely mechanical, no semantic judgment" logic as an LLM step produced run-to-run inconsistent file counts, role classifications, and security_priority scores on an *unchanged* repo, because per-file interpretation over hundreds of files drifted under context/attention pressure. A real script gives byte-identical output on repeated runs.

## Your job

1. Run:
   ```bash
   python3 harness/scripts/crawl_tree_sitter.py <repo-path> --manifest language-manifest.json --out crawl-output.json
   ```
   (paths relative to your working directory; use absolute paths if unsure). If `harness/scripts/crawl_tree_sitter.py` is not found relative to the current directory, locate it under the repo root's `harness/scripts/` and use that path instead.
2. Read the resulting `crawl-output.json` and relay/summarize it — do not re-derive or second-guess its role/priority assignments; the script is the source of truth for this step.
3. Print the script's own stdout summary verbatim (file counts, role distribution, security priority distribution) — do not recompute these from the JSON yourself.

## Input

`$ARGUMENTS` format: `<repo-path> --manifest language-manifest.json [--out <path>] [--ts-bin <path>]`

- `<repo-path>` — required. Absolute path to the repository root.
- `--manifest <path>` — path to `language-manifest.json` (default: `./language-manifest.json`)
- `--out <path>` — output path (default: `./crawl-output.json`)
- `--ts-bin <path>` — path to tree-sitter CLI binary (default: auto-detect)

Pass these through to the script unchanged.

## If tree-sitter is not installed

The script itself detects this and writes the stub `{ "ts_available": false, "reason": "tree_sitter_not_installed" }` to the output path, then exits 0 — do not treat this as a failure. Relay its printed message:
```
crawl-tree-sitter: tree-sitter CLI not installed — AST crawl skipped.
  Install: https://tree-sitter.github.io/tree-sitter/using-parsers#installation
  Effect : pipeline falls back to heuristic crawl-python/crawl-typescript/crawl-java skills.
  To suppress: pass --skip-tree-sitter to sast-full-scan.
```

## Output schema (crawl-output.json)

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
      "routes": [ { "method": "POST", "path": "/login", "handler": "loginHandler", "line": 10 } ],
      "user_input_sources": [ { "type": "req.body", "field": "email", "line": 15 } ]
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
        "functions": [ { "name": "loginHandler", "line": 12, "params": ["req", "res"], "is_async": true, "exported": true } ],
        "imports": [ { "source": "express", "names": ["Router"] } ],
        "routes": [ { "method": "POST", "path": "/login", "handler": "loginHandler", "line": 10 } ],
        "user_input_sources": [ { "type": "req.body", "field": "email", "line": 15 } ],
        "dangerous_patterns": [ { "type": "sql_template_literal", "line": 45, "snippet": "SELECT * FROM users WHERE email = '${email}'" } ],
        "calls_to": ["sequelize.query", "bcrypt.compare", "jwt.sign"]
      }
    }
  ],
  "security_priority_distribution": { "5": 12, "4": 18, "3": 34, "2": 56, "1": 89 },
  "dangerous_pattern_summary": { "sql_template_literal": 3, "eval": 1 },
  "skipped_files": [],
  "warnings": []
}
```

**Key difference from heuristic crawl:** the `ast` object on each file gives downstream skills (Joern, find-vulns) exact data they previously had to infer:
- `user_input_sources[]` — Joern uses these as precise taint source parameter hints
- `dangerous_patterns[]` — find-vulns uses these to know which sink types exist in which files (no discovery needed for known patterns)
- `routes[]` — exact HTTP method + path for every route handler

## Role classification and priority scoring (implemented in the script)

Role per file (first matching rule wins): `entry_point` (has route registrations or Next.js `pages/`/`app/`-root convention), `middleware` ((req,res,next) shape), `service`/`dao` (name suffix + call patterns), `model` (no function bodies), `component` (JSX with no routes), `config` (name pattern), else `util`.

`security_priority` 1–5, driven by dangerous-pattern tier (5: eval/exec/SQLi/XSS/deserialization sinks; 4: SSRF/path-traversal/jwt-sign/weak-hash; 3: user-input sources present; 2: calls into a tier-≥3 file, OR has real function logic and a utility/helper/manager/extractor/tool-pattern path — checked per path segment, e.g. `ls_manager/downloaders.py` matches on the directory name even though the filename alone doesn't; 1: no risk signals). The utility-path rule exists because such files often receive attacker-controlled data (a file path, uploaded bytes) as a plain function parameter rather than reading it directly from `req.*`/`request.*` — the only shape our user-input-source detection recognizes — so without this floor they can score tier 1 and never enter the `find-vulns-*` scan queue (which only includes `security_priority >= 2`) at all, even when reachable from a real entry point. See `harness/scripts/crawl_tree_sitter.py` for the exact rules if you need to verify a specific file's score.

## Constraints

- Do not re-implement or "correct" the script's role/priority output by re-reading files yourself — that reintroduces the non-determinism this rewrite was meant to remove. If a classification looks wrong, that's a script bug to fix in `crawl_tree_sitter.py`, not something to override per-run.
- The stub `{ "ts_available": false }` must always be valid JSON so `sast-full-scan` can parse it without errors — this is guaranteed by the script.

## Downstream consumers

- `/joern-parse` — reads `entry_points[].user_input_sources[]` to configure taint sources precisely; reads `dangerous_patterns[]` to know which sink types to prioritize in CPG queries
- `/find-vulns-typescript`, `/find-vulns-python`, `/find-vulns-java` — reads `files[].ast.dangerous_patterns[]` to pre-confirm known dangerous patterns without re-discovering them; reads `security_priority` for scan queue ordering
- `/sast-full-scan` — if `ts_available: true`, skips the standard language-specific crawl skills in Group 1
