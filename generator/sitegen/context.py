"""Deployment context loading and aliases."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class DeploymentContext:
    """All parameters that control what kind of site gets generated."""

    context_name: str = "university"
    org_types: list[str] = field(default_factory=lambda: [
        "Microsoft Exchange OWA (Outlook Web Access)",
        "Webmail service (Roundcube, Horde, etc.)",
        "Student information system / course enrollment portal",
        "Research data management portal",
        "Library catalog and search system",
        "VPN / Network access portal",
        "IT helpdesk / ticket system",
        "File sharing service (Nextcloud-like)",
        "Internal wiki / knowledge base",
        "Exam registration portal",
    ])
    user_roles: list[str] = field(default_factory=lambda: [
        "admin", "student", "professor", "staff"
    ])
    name_style: str = "international, appropriate for the specified country"
    brand_color: str = ""
    logo_url: str = ""
    reference_organizations: list[str] = field(default_factory=list)
    prompt_guidance: str = ""
    os_options: list[str] = field(default_factory=lambda: [
        "Ubuntu 24.04 LTS",
        "Ubuntu 22.04 LTS",
        "Debian 12 (Bookworm)",
    ])
    ssh_banner_options: list[str] = field(default_factory=lambda: [
        "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5",
        "SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u3",
        "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10",
    ])
    tls_country: str = ""
    # Landing page tab configuration
    offerings_label: str = "Services"
    personnel_label: str = "Our Team"
    personnel_role_filter: list[str] = field(default_factory=list)
    # Dashboard tab configuration
    dashboard_persona: str = "user"
    dashboard_tabs: list[str] = field(default_factory=lambda: [
        "Overview", "Tasks", "Reports"
    ])

    @classmethod
    def from_json(cls, path: str) -> "DeploymentContext":
        """Load a DeploymentContext from a JSON file."""
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        ctx = cls()
        for key, value in data.items():
            if hasattr(ctx, key):
                setattr(ctx, key, value)
        return ctx

    @classmethod
    def builtin(cls, name: str) -> "DeploymentContext":
        """Load one of the bundled context presets by name."""
        contexts_dir = Path(__file__).resolve().parents[1] / "contexts"
        context_name = CONTEXT_ALIASES.get(name.strip().lower(), name)
        preset_path = contexts_dir / f"{context_name}.json"
        if preset_path.exists():
            return cls.from_json(str(preset_path))
        available = sorted(p.stem for p in contexts_dir.glob("*.json"))
        raise ValueError(
            f"Unknown built-in context '{name}'. Available: {available}"
        )


CONTEXT_ALIASES = {
    "ai": "ai_company",
    "ai-company": "ai_company",
    "ai_company": "ai_company",
    "artificial-intelligence": "ai_company",
    "artificial_intelligence": "ai_company",
    "llm": "ai_company",
    "llm-provider": "ai_company",
    "llm_provider": "ai_company",
    "model-provider": "ai_company",
    "model_provider": "ai_company",
}


def build_context(context_arg: str) -> DeploymentContext:
    """Resolve a CLI --context value to a DeploymentContext."""
    if context_arg.endswith(".json") or os.path.sep in context_arg:
        if not os.path.exists(context_arg):
            raise FileNotFoundError(f"Context file not found: {context_arg}")
        return DeploymentContext.from_json(context_arg)

    return DeploymentContext.builtin(context_arg)

