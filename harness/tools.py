import subprocess
from pathlib import Path

TOOL_SCHEMAS = [
    {
        "name": "read_file",
        "description": "Read a file from disk. Relative paths resolve to the scan workdir first, then the repo root.",
        "input_schema": {
            "type": "object",
            "properties": {"path": {"type": "string"}},
            "required": ["path"],
        },
    },
    {
        "name": "write_file",
        "description": "Write content to a file. Relative paths resolve to the scan workdir.",
        "input_schema": {
            "type": "object",
            "properties": {
                "path": {"type": "string"},
                "content": {"type": "string"},
            },
            "required": ["path", "content"],
        },
    },
    {
        "name": "run_bash",
        "description": "Run a shell command. CWD is the scan workdir. Use absolute paths for repo files.",
        "input_schema": {
            "type": "object",
            "properties": {"command": {"type": "string"}},
            "required": ["command"],
        },
    },
    {
        "name": "list_dir",
        "description": "List contents of a directory.",
        "input_schema": {
            "type": "object",
            "properties": {"path": {"type": "string"}},
            "required": ["path"],
        },
    },
    {
        "name": "search_files",
        "description": "Search for files matching a glob pattern under a directory.",
        "input_schema": {
            "type": "object",
            "properties": {
                "pattern":   {"type": "string", "description": "Glob pattern e.g. **/*.py"},
                "directory": {"type": "string", "description": "Root directory (default: repo root)"},
            },
            "required": ["pattern"],
        },
    },
]


def make_executor(workdir: Path, repo_path: Path):
    """Return a tool executor bound to this scan's workdir and repo."""

    def resolve(path_str: str) -> Path:
        p = Path(path_str)
        if p.is_absolute():
            return p
        # prefer workdir file if it exists, else fall back to repo
        candidate = workdir / p
        if candidate.exists():
            return candidate
        return repo_path / p

    def execute(name: str, inputs: dict) -> str:
        try:
            if name == "read_file":
                p = resolve(inputs["path"])
                return p.read_text(encoding="utf-8", errors="replace")

            if name == "write_file":
                p = workdir / inputs["path"]   # writes always go to workdir
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_text(inputs["content"], encoding="utf-8")
                return f"Written: {p}"

            if name == "run_bash":
                result = subprocess.run(
                    inputs["command"],
                    shell=True, capture_output=True, text=True,
                    cwd=workdir, timeout=300,
                )
                out = result.stdout + result.stderr
                return out[:10000] if out else "(no output)"

            if name == "list_dir":
                p = resolve(inputs["path"])
                entries = sorted(p.iterdir()) if p.is_dir() else []
                return "\n".join(str(e.name) for e in entries) or "(empty)"

            if name == "search_files":
                root = resolve(inputs.get("directory", str(repo_path)))
                matches = list(root.glob(inputs["pattern"]))
                return "\n".join(str(m) for m in matches[:300]) or "(no matches)"

            return f"ERROR: unknown tool '{name}'"
        except FileNotFoundError as e:
            return f"ERROR: file not found — {e}"
        except Exception as e:
            return f"ERROR: {type(e).__name__}: {e}"

    return execute
