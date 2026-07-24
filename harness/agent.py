"""Agentic loop: loads one SAST skill prompt and runs it via `claude --print` CLI."""

import asyncio
import json
from pathlib import Path
from typing import Callable, Awaitable, Tuple

import config

# Timeout per skill in seconds — 2 hours to handle large repos (400+ file TypeScript scans)
SKILL_TIMEOUT = 7200

# claude tracks tool-use trust per exact directory path, not by walking up to
# a parent git root's settings — and every run gets a brand-new `workdir`
# (timestamped), so a settings.local.json at the project root alone is not
# enough. Without a local grant here, --print blocks forever on the first
# Write/Bash/Read call with no way to approve it (no TTY, no human present).
_WORKDIR_PERMISSIONS = {"permissions": {"allow": ["Bash", "Write", "Edit", "Read"]}}


def _ensure_workdir_trust(workdir: Path) -> None:
    settings_dir = workdir / ".claude"
    settings_file = settings_dir / "settings.local.json"
    if settings_file.exists():
        return
    settings_dir.mkdir(parents=True, exist_ok=True)
    settings_file.write_text(json.dumps(_WORKDIR_PERMISSIONS, indent=2), encoding="utf-8")


async def run_skill(
    skill_name: str,
    repo_path: Path,
    workdir: Path,
    extra_context: str = "",
    emit: Callable[[dict], Awaitable[None]] = None,
) -> Tuple[str, dict]:
    """
    Load skill_name.md, run it through `claude --print`, return (final text output, usage).
    CWD is set to workdir so the skill's file writes land in the right place.
    emit() is called with progress events for SSE streaming.

    `usage` is {"input_tokens", "output_tokens", "cache_creation_input_tokens",
    "cache_read_input_tokens", "cost_usd"} — all 0/0.0 if the CLI's JSON envelope
    couldn't be parsed (e.g. a claude CLI version predating --output-format json),
    so a parse failure degrades to "no cost data" rather than crashing the step.
    """
    skill_file = config.SKILLS_DIR / f"{skill_name}.md"
    if not skill_file.exists():
        raise FileNotFoundError(f"Skill not found: {skill_file}")

    skill_prompt = skill_file.read_text(encoding="utf-8")

    context = (
        f"Repository path: {repo_path}\n"
        f"Working directory (write all output files here): {workdir}\n"
        f"{extra_context}\n\n"
        "EXECUTION MODE — read before starting: this is a one-shot, non-interactive "
        "invocation (`claude --print`). There is no follow-up turn and no notification "
        "mechanism — once this response ends, no one reads any further output from you "
        "and nothing you started in the background will ever be checked on again. Do not "
        "run any command with a backgrounding flag (e.g. run_in_background) and do not "
        "defer to 'I'll wait for the background task notification' or similar. Every "
        "command you run must be waited on synchronously to real completion before you "
        "end your turn. If a step is slow, that is expected — block on it rather than "
        "backgrounding it. Do not end your turn until the required output file(s) for "
        "this skill actually exist on disk."
    )

    full_prompt = f"{skill_prompt}\n\n---\n{context}"

    if emit:
        await emit({"type": "skill_start", "skill": skill_name})

    _ensure_workdir_trust(workdir)

    # Write prompt to a temp file to avoid shell quoting issues with long prompts
    prompt_file = workdir / f".prompt-{skill_name}.txt"
    prompt_file.write_text(full_prompt, encoding="utf-8")

    try:
        # Every skill invocation here is fully unattended (--print, no TTY, no
        # human present to approve a Write/Bash prompt). Without a permission
        # grant the subprocess blocks forever on the first tool call in any
        # environment that hasn't separately established trust for this
        # project (e.g. a fresh VPS, unlike a dev machine where an interactive
        # Claude Code session already trusts the repo). --dangerously-skip-permissions
        # / --permission-mode bypassPermissions are both refused when running
        # as root (a deliberate CLI safety check) — common on single-user VPS
        # boxes — so trust is granted instead via a project-level
        # .claude/settings.local.json permissions allowlist (see repo root),
        # which is a different mechanism and isn't subject to that check.
        # --add-dir: the sandbox otherwise restricts file access to cwd
        # (workdir) only. repo_path is a sibling directory the skill must
        # read from (source files, config files, etc.) — without this flag
        # every skill fails identically to "target repo not accessible".
        # --add-dir is variadic (accepts multiple directories) and greedily
        # consumes subsequent bare arguments, so it MUST come after the
        # prompt argument — placed before it, it silently swallows
        # "@prompt-file" as another directory and leaves no prompt at all.
        proc = await asyncio.create_subprocess_exec(
            "claude", "--print", f"@{prompt_file}", "--add-dir", str(repo_path),
            "--output-format", "json",
            cwd=str(workdir),
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        try:
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=SKILL_TIMEOUT)
        except asyncio.TimeoutError:
            proc.kill()
            raise RuntimeError(f"Skill '{skill_name}' timed out after {SKILL_TIMEOUT}s")
        except asyncio.CancelledError:
            proc.kill()
            raise

        if proc.returncode != 0:
            err = stderr.decode(errors="replace")[:600]
            raise RuntimeError(f"claude exited {proc.returncode}: {err}")

        raw_stdout = stdout.decode(errors="replace")
        output, usage = _parse_json_envelope(raw_stdout)

    finally:
        prompt_file.unlink(missing_ok=True)

    if emit:
        await emit({
            "type": "skill_complete",
            "skill": skill_name,
            "summary": output[:300],
        })

    return output, usage


def _parse_json_envelope(raw_stdout: str) -> Tuple[str, dict]:
    """Extract the final text + token/cost usage from `--output-format json`'s
    single-object envelope. Falls back to treating raw_stdout as plain text
    with zeroed usage if it isn't valid JSON (e.g. an older claude CLI that
    doesn't support --output-format json), so a schema/version mismatch never
    fails the whole skill step over a bookkeeping feature."""
    empty_usage = {
        "input_tokens": 0, "output_tokens": 0,
        "cache_creation_input_tokens": 0, "cache_read_input_tokens": 0,
        "cost_usd": 0.0,
    }
    try:
        envelope = json.loads(raw_stdout)
    except (json.JSONDecodeError, ValueError):
        return raw_stdout, empty_usage

    result_text = envelope.get("result", raw_stdout)
    raw_usage = envelope.get("usage") or {}
    usage = {
        "input_tokens": raw_usage.get("input_tokens", 0),
        "output_tokens": raw_usage.get("output_tokens", 0),
        "cache_creation_input_tokens": raw_usage.get("cache_creation_input_tokens", 0),
        "cache_read_input_tokens": raw_usage.get("cache_read_input_tokens", 0),
        "cost_usd": envelope.get("total_cost_usd", 0.0),
    }
    return result_text, usage
