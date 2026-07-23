"""Agentic loop: loads one SAST skill prompt and runs it via `claude --print` CLI."""

import asyncio
from pathlib import Path
from typing import Callable, Awaitable

import config

# Timeout per skill in seconds — 2 hours to handle large repos (400+ file TypeScript scans)
SKILL_TIMEOUT = 7200


async def run_skill(
    skill_name: str,
    repo_path: Path,
    workdir: Path,
    extra_context: str = "",
    emit: Callable[[dict], Awaitable[None]] = None,
) -> str:
    """
    Load skill_name.md, run it through `claude --print`, return the final text output.
    CWD is set to workdir so the skill's file writes land in the right place.
    emit() is called with progress events for SSE streaming.
    """
    skill_file = config.SKILLS_DIR / f"{skill_name}.md"
    if not skill_file.exists():
        raise FileNotFoundError(f"Skill not found: {skill_file}")

    skill_prompt = skill_file.read_text(encoding="utf-8")

    context = (
        f"Repository path: {repo_path}\n"
        f"Working directory (write all output files here): {workdir}\n"
        f"{extra_context}"
    )

    full_prompt = f"{skill_prompt}\n\n---\n{context}"

    if emit:
        await emit({"type": "skill_start", "skill": skill_name})

    # Write prompt to a temp file to avoid shell quoting issues with long prompts
    prompt_file = workdir / f".prompt-{skill_name}.txt"
    prompt_file.write_text(full_prompt, encoding="utf-8")

    try:
        proc = await asyncio.create_subprocess_exec(
            "claude", "--print", f"@{prompt_file}",
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

        output = stdout.decode(errors="replace")

    finally:
        prompt_file.unlink(missing_ok=True)

    if emit:
        await emit({
            "type": "skill_complete",
            "skill": skill_name,
            "summary": output[:300],
        })

    return output
