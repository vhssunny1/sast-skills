"""Agentic loop: loads one SAST skill prompt and runs it to completion via the Anthropic API."""

import asyncio
from pathlib import Path
from typing import Callable, Awaitable

import anthropic

import config
from tools import TOOL_SCHEMAS, make_executor


async def run_skill(
    skill_name: str,
    repo_path: Path,
    workdir: Path,
    extra_context: str = "",
    emit: Callable[[dict], Awaitable[None]] = None,
) -> str:
    """
    Load skill_name.md, run the agentic loop, return the final text output.
    emit() is called with progress events for SSE streaming.
    """
    skill_file = config.SKILLS_DIR / f"{skill_name}.md"
    if not skill_file.exists():
        raise FileNotFoundError(f"Skill not found: {skill_file}")

    skill_prompt = skill_file.read_text(encoding="utf-8")
    execute_tool = make_executor(workdir, repo_path)

    context = (
        f"Repository path: {repo_path}\n"
        f"Working directory (write all output files here): {workdir}\n"
        f"{extra_context}"
    )

    messages = [{"role": "user", "content": f"{skill_prompt}\n\n---\n{context}"}]

    if emit:
        await emit({"type": "skill_start", "skill": skill_name})

    client = anthropic.AsyncAnthropic(api_key=config.ANTHROPIC_API_KEY)
    iterations = 0

    while iterations < config.MAX_SKILL_ITERATIONS:
        iterations += 1
        response = await client.messages.create(
            model=config.MODEL,
            max_tokens=8096,
            tools=TOOL_SCHEMAS,
            messages=messages,
        )

        if response.stop_reason == "end_turn":
            final_text = next(
                (b.text for b in response.content if hasattr(b, "text")), ""
            )
            if emit:
                await emit({
                    "type": "skill_complete",
                    "skill": skill_name,
                    "summary": final_text[:300],
                })
            return final_text

        # execute tool calls
        messages.append({"role": "assistant", "content": response.content})
        tool_results = []
        for block in response.content:
            if block.type == "tool_use":
                if emit:
                    await emit({
                        "type": "tool_call",
                        "skill": skill_name,
                        "tool": block.name,
                        "detail": str(block.input)[:120],
                    })
                result = await asyncio.get_event_loop().run_in_executor(
                    None, execute_tool, block.name, block.input
                )
                tool_results.append({
                    "type": "tool_result",
                    "tool_use_id": block.id,
                    "content": str(result),
                })
        messages.append({"role": "user", "content": tool_results})

    raise RuntimeError(f"Skill '{skill_name}' hit max iterations ({config.MAX_SKILL_ITERATIONS})")
