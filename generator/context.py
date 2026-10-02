"""
DeploymentContext dataclass and SERVER_PROFILES dictionary.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path


# ─── Server profiles ──────────────────────────────────────────────────────────

SERVER_PROFILES: dict[str, dict] = {
    "apache_2_4": {
        "server_header": "Apache/2.4.62 (Ubuntu)",
        "cookie_name": "PHPSESSID",
        "powered_by": "PHP/8.2.27",
        "error_style": "apache",
    },
    "nginx_1_24": {
        "server_header": "nginx/1.24.0",
        "cookie_name": "session_id",
        "powered_by": None,
        "error_style": "nginx",
    },
    "iis_10": {
        "server_header": "Microsoft-IIS/10.0",
        "cookie_name": "ASP.NET_SessionId",
        "powered_by": "ASP.NET",
        "error_style": "iis",
    },
    "tomcat_9": {
        "server_header": "Apache-Coyote/1.1",
        "cookie_name": "JSESSIONID",
        "powered_by": None,
        "error_style": "tomcat",
    },
}


# ─── Deployment context ───────────────────────────────────────────────────────

@dataclass
class DeploymentContext:
    """All the parameters that control how site content is generated."""

    context_name: str = "university"
    org_types: list = field(
        default_factory=lambda: [
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
        ]
    )
    user_roles: list = field(
        default_factory=lambda: ["admin", "student", "professor", "staff"]
    )
    # How to describe what kinds of names/users should appear
    name_style: str = "international, appropriate for the specified country"
    # Brand color injected into HTML prompt; empty = let LLM decide
    brand_color: str = ""
    # Logo URL to show in nav bar; empty = LLM picks a plausible placeholder
    logo_url: str = ""
    # OS options the SSH profile can pick from
    os_options: list = field(
        default_factory=lambda: [
            "Ubuntu 24.04 LTS",
            "Ubuntu 22.04 LTS",
            "Debian 12 (Bookworm)",
        ]
    )
    # SSH banner strings matching the OS options
    ssh_banner_options: list = field(
        default_factory=lambda: [
            "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5",
            "SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u3",
            "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10",
        ]
    )
    # ISO 3166-1 alpha-2; empty = LLM picks
    tls_country: str = ""

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
        contexts_dir = Path(__file__).parent / "contexts"
        preset_path = contexts_dir / f"{name}.json"
        if preset_path.exists():
            return cls.from_json(str(preset_path))
        raise ValueError(
            f"Unknown built-in context '{name}'. "
            f"Available: {[p.stem for p in contexts_dir.glob('*.json')]}"
        )
