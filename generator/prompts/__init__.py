"""
Prompt loader for the generator.

All prompt templates live as JSON files under generator/prompts/.
Each JSON file has either:
  - a ``template`` key (single string) — legacy format
  - a ``template_lines`` key (array of strings) — preferred, IDE-readable format
    The lines are joined with newlines when loaded.
"""

from __future__ import annotations

import json
from pathlib import Path

_PROMPTS_DIR = Path(__file__).parent


def load(name: str) -> str:
    """Return the prompt template string for *name* (without .json extension)."""
    path = _PROMPTS_DIR / f"{name}.json"
    if not path.exists():
        raise FileNotFoundError(
            f"Prompt template '{name}' not found at {path}. "
            f"Available: {[p.stem for p in _PROMPTS_DIR.glob('*.json')]}"
        )
    with open(path, encoding="utf-8") as f:
        data = json.load(f)

    if "template_lines" in data:
        return "\n".join(data["template_lines"])
    return data["template"]


def safe_format(template: str, **kwargs) -> str:
    """
    Safely format a prompt template by replacing {key} with its value.
    Unlike str.format(), this ignores any other {braces} in the text, meaning
    you do not need to double-escape JSON structures in the prompt templates.
    """
    for key, value in kwargs.items():
        template = template.replace(f"{{{key}}}", str(value))
    return template


# Pre-load all prompts at import time so callers can use them as constants.
APP_SPEC_PROMPT: str = load("app_spec")
HTML_PAGE_PROMPT: str = load("html_page")
HTML_CRITIC_PROMPT: str = load("html_critic")
HTML_REVISION_PROMPT: str = load("html_revision")
SECURITY_CRITIC_PROMPT: str = load("security_critic")
SSH_PROFILE_PROMPT: str = load("ssh_profile")

