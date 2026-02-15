"""Compatibility bridges for Agent Skills, AGENTS.md."""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from .passport import Skill


def import_agent_skill(skill_dir: str) -> Skill:
    """Read an Agent Skills folder and convert to a Skill."""
    skill_md_path = Path(skill_dir) / "SKILL.md"
    content = skill_md_path.read_text(encoding="utf-8")
    name = Path(skill_dir).name
    description = _extract_first_line(content)
    capabilities = _infer_capabilities(content)
    return Skill(
        name=name,
        version="1.0.0",
        description=description,
        capabilities=capabilities,
        source=f"agent-skills://{name}",
        hash="",
    )


def export_agent_skill(skill: Skill, output_dir: str) -> None:
    """Write a Skill as an Agent Skills folder."""
    skill_dir = Path(output_dir) / skill.name
    skill_dir.mkdir(parents=True, exist_ok=True)

    md = f"# {skill.name}\n\n{skill.description}\n\nVersion: {skill.version}\n\n## Capabilities\n\n"
    for cap in skill.capabilities:
        md += f"- {cap}\n"
    (skill_dir / "SKILL.md").write_text(md, encoding="utf-8")

    meta = {"name": skill.name, "version": skill.version, "description": skill.description,
            "capabilities": skill.capabilities, "hash": skill.hash}
    if skill.source:
        meta["source"] = skill.source
    (skill_dir / "metadata.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")


class AgentsMD:
    def __init__(self, raw: str = "", instructions: list[str] | None = None,
                 constraints: list[str] | None = None, tools: list[str] | None = None):
        self.raw = raw
        self.instructions = instructions or []
        self.constraints = constraints or []
        self.tools = tools or []


def load_agents_md(repo_path: str) -> AgentsMD:
    """Read and parse an AGENTS.md file."""
    agents_path = Path(repo_path) / "AGENTS.md"
    content = agents_path.read_text(encoding="utf-8")
    result = AgentsMD(raw=content)
    section = ""
    for line in content.split("\n"):
        trimmed = line.strip()
        lower = trimmed.lower()
        if trimmed.startswith("#"):
            if "instruction" in lower or "rules" in lower:
                section = "instructions"
            elif "constraint" in lower or "restriction" in lower:
                section = "constraints"
            elif "tool" in lower or "mcp" in lower:
                section = "tools"
            else:
                section = ""
            continue
        if trimmed.startswith("- ") or trimmed.startswith("* "):
            item = trimmed.lstrip("-* ")
            if section == "instructions":
                result.instructions.append(item)
            elif section == "constraints":
                result.constraints.append(item)
            elif section == "tools":
                result.tools.append(item)
    return result


def _extract_first_line(content: str) -> str:
    for line in content.split("\n"):
        trimmed = line.strip()
        if trimmed and not trimmed.startswith("#"):
            return trimmed
    return ""


def _infer_capabilities(content: str) -> list[str]:
    lower = content.lower()
    caps: list[str] = []
    if "code" in lower or "develop" in lower:
        caps.append("code_write")
    if "test" in lower:
        caps.append("test_run")
    if "debug" in lower:
        caps.append("debug")
    if "build" in lower:
        caps.append("build")
    if "review" in lower or "audit" in lower:
        caps.append("code_review")
    if "data" in lower or "analyz" in lower:
        caps.append("data_read")
    return caps or ["general"]
