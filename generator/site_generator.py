"""
Core site-generation logic: generate_site() and build_context() helper.
"""

from __future__ import annotations

import json
import os
import re
import uuid
from datetime import datetime
from pathlib import Path
from time import sleep
from typing import Optional

from .client import OllamaClient
from .context import DeploymentContext, SERVER_PROFILES
from .html_utils import (
    clean_html,
    extract_json,
    validate_html_basic,
    verify_vulnerability_static,
)
from .nuclei_utils import generate_nuclei_templates
from .sitegen.prompts import (
    APP_SPEC_PROMPT,
    HTML_CRITIC_PROMPT,
    HTML_PAGE_PROMPT,
    HTML_REVISION_PROMPT,
    SECURITY_CRITIC_PROMPT,
    SSH_PROFILE_PROMPT,
)
from .sitegen.pipeline import generate_site


def _org_slug(organization: str) -> str:
    """Convert an organization name to a filesystem-safe slug."""
    slug = organization.lower()
    slug = re.sub(r"[^a-z0-9]+", "_", slug)
    slug = slug.strip("_")
    return slug[:64]  # cap length


def build_context(context_arg: str) -> DeploymentContext:
    """Resolve a --context argument to a DeploymentContext.

    If *context_arg* ends with ``.json`` or contains a path separator it is
    treated as a file path; otherwise it is looked up as a built-in preset
    name (e.g. ``university``, ``hospital``).
    """
    if context_arg.endswith(".json") or os.path.sep in context_arg:
        if not os.path.exists(context_arg):
            raise FileNotFoundError(f"Context file not found: {context_arg}")
        return DeploymentContext.from_json(context_arg)
    return DeploymentContext.builtin(context_arg)


def generate_site(
    client: OllamaClient,
    coding_model: str,
    save_path: str,
    ctx: DeploymentContext,
    reasoning_model: Optional[str] = None,
    country: str = "",
    language: str = "English",
    temperature: float = 0.3,
    vulnerability_preset: Optional[str] = None,
) -> Optional[str]:
    """Generate a complete honeypot site definition and save it to *save_path*.

    Args:
        client: OllamaClient instance.
        model: Ollama model name.
        save_path: Directory to write the output JSON.
        ctx: DeploymentContext controlling what kind of org is simulated.
        country: ISO-3166 country code hint (e.g. ``"US"``, ``"DE"``) or
            ``""`` for any country.
        language: Natural language for UI content (e.g. ``"English"``).
        temperature: LLM temperature used for spec / SSH generation.

    Returns:
        ``site_id`` string on success, ``None`` on failure.
    """
    site_id = str(uuid.uuid4())
    print(
        f"\n[*] Generating site {site_id[:8]}... "
        f"(coding_model={coding_model}, reasoning_model={reasoning_model}, context={ctx.context_name}, "
        f"country={country or 'any'}, lang={language})"
    )

    if reasoning_model is None:
        reasoning_model = coding_model

    # Build prompt-friendly strings from context lists
    org_types_list = "\n".join(f"- {t}" for t in ctx.org_types)
    roles_list = ", ".join(ctx.user_roles)
    country_hint = country if country else "any country (your choice)"
    os_options_str = "\n".join(f"- {o}" for o in ctx.os_options)

    # ── Step 0: Load vulnerability preset ───────────────────────────
    vuln_context = ""
    vuln_meta = {}
    if vulnerability_preset:
        vuln_path = (
            Path(__file__).parent / "vulnerabilities" / f"{vulnerability_preset}.json"
        )
        if vuln_path.exists():
            with open(vuln_path, encoding="utf-8") as f:
                vuln_meta = json.load(f)
            print(f"  [+] Using vulnerability preset: {vuln_meta.get('type')}")
            vuln_context = (
                "\nCRITICAL REQUIREMENT: The application MUST have the following "
                f"vulnerability: {vuln_meta.get('type')}.\n"
                f"Description: {vuln_meta.get('description')}\n"
                f"Target Route: {vuln_meta.get('target_route')}\n"
                f"Target Parameter: {vuln_meta.get('parameter')}\n"
                f"Exploit Hint: {vuln_meta.get('exploit_hint')}\n"
            )
            if "requirements" in vuln_meta:
                vuln_context += "Specific implementation requirements:\n"
                vuln_context += "\n".join(f"- {r}" for r in vuln_meta["requirements"])
        else:
            print(f"  [⚠] Vulnerability preset '{vulnerability_preset}' not found.")
    print("  [1/4] Generating app specification...")
    try:
        spec_prompt = APP_SPEC_PROMPT.format(
            context_name=ctx.context_name,
            org_types_list=org_types_list,
            country_hint=country_hint,
            name_style=ctx.name_style,
            language=language,
            roles_list=roles_list,
        )
        if vuln_context:
            spec_prompt += f"\n{vuln_context}"

        raw_spec = client.generate(spec_prompt, coding_model, temperature=temperature)
        app_spec = extract_json(raw_spec)
    except Exception as e:
        print(f"  [!] Failed to generate app spec: {e}")
        return None

    app_name = app_spec.get("app_name", f"{ctx.context_name.title()} Portal")
    organization = app_spec.get("organization", "Example Organization")
    domain = app_spec.get("domain", "portal.example.org")
    app_country = app_spec.get("country", country or "")
    server_profile = app_spec.get("server_profile", "apache_2_4")
    if server_profile not in SERVER_PROFILES:
        server_profile = "apache_2_4"

    print(
        f"  [✓] App: {app_name} | Org: {organization} | "
        f"Profile: {server_profile} | Domain: {domain}"
    )

    # ── Step 2: Generate HTML pages per route ────────────────────────
    print("  [2/4] Generating HTML pages...")
    route_responses: dict = {}
    routes = app_spec.get("routes", {})

    # Build navigation route list
    nav_routes = ", ".join(
        f"{path} ({info.get('page_title', info.get('description', 'Page'))})"
        for path, info in routes.items()
    )

    # Brand color / logo instructions
    if ctx.brand_color:
        brand_color_line = f"Primary brand color: {ctx.brand_color}"
        brand_color_instruction = (
            f"Use the brand color {ctx.brand_color} for headers, buttons, and accents"
        )
    else:
        brand_color_line = (
            "Primary brand color: pick a professional color appropriate "
            "for the organization"
        )
        brand_color_instruction = (
            "Choose a professional brand color appropriate for the "
            "organization type — use it consistently for headers, buttons, "
            "and accents"
        )

    logo_line = (
        f"Logo URL: {ctx.logo_url}"
        if ctx.logo_url
        else "Logo: use a text-based logo or leave it as the organization name"
    )

    for path, info in routes.items():
        route_responses[path] = {}
        page_title = info.get("page_title", info.get("description", app_name))

        for method in info.get("methods", ["GET"]):
            # Determine user state
            if info.get("auth_required", False):
                users = app_spec.get("users", [])
                user = next(
                    (u for u in users if u.get("role") != "admin"),
                    users[0] if users else {},
                )
                user_state = (
                    f"Logged in as {user.get('display_name', 'User')} "
                    f"({user.get('role', 'user')}, {user.get('email', '')})"
                )
            else:
                user_state = "Not authenticated (anonymous visitor)"

            prompt = HTML_PAGE_PROMPT.format(
                app_name=app_name,
                organization=organization,
                country=app_country or country_hint,
                method=method,
                path=path,
                page_description=info.get("description", ""),
                page_title=page_title,
                user_state=user_state,
                nav_routes=nav_routes,
                brand_color_line=brand_color_line,
                logo_line=logo_line,
                context_guidance="No additional context guidance.",
                ux_plan="Use professional enterprise dashboard layout.",
                route_plan="Follow the page description for layout.",
                site_contract="Use only the listed routes for navigation.",
                brand_color_instruction=brand_color_instruction,
                context_name=ctx.context_name,
                language=language,
            )

            # Inject specific vulnerability instructions into the page prompt
            # if this route is the target.
            vuln_spec = app_spec.get("vulnerability", {})
            if (
                vuln_spec
                and isinstance(vuln_spec, dict)
                and vuln_spec.get("target_route") == path
            ):
                prompt += (
                    "\nSECURITY REQUIREMENT: This specific route MUST implement the "
                    f"intended vulnerability: {vuln_spec.get('type')}.\n"
                    f"Vulnerable parameter: {vuln_spec.get('parameter')}\n"
                    f"Implementation detail: {vuln_spec.get('exploit_hint')}\n"
                    "Ensure the vulnerability is REAL and exploitable in the HTML/JS, "
                    "not just described in text."
                )

            try:
                raw_html = client.generate(prompt, coding_model, temperature=0.2)
                html = clean_html(raw_html)

                # Validate and attempt repair on second pass
                valid, issues = validate_html_basic(html)
                if not valid:
                    print(
                        f"    [⚠] {method} {path}: "
                        f"{', '.join(issues)} — attempting repair"
                    )
                    html = clean_html(html)

                # --- Critic loop ---
                print(f"    [~] {method} {path}: asking critic...")
                critic_prompt = HTML_CRITIC_PROMPT.format(
                    app_name=app_name,
                    organization=organization,
                    method=method,
                    path=path,
                    page_description=info.get("description", ""),
                    site_contract="Use only the listed routes for navigation.",
                    language=language,
                    html=html,
                )
                critic_feedback = client.generate(
                    critic_prompt, reasoning_model, temperature=0.2
                ).strip()

                if "APPROVED" not in critic_feedback.upper():
                    print(
                        f"    [~] {method} {path}: "
                        "Critic suggested improvements. Revising..."
                    )
                    revision_prompt = HTML_REVISION_PROMPT.format(
                        app_name=app_name,
                        organization=organization,
                        method=method,
                        path=path,
                        page_description=info.get("description", ""),
                        site_contract="Use only the listed routes for navigation.",
                        feedback=critic_feedback,
                        html=html,
                    )
                    raw_html_revised = client.generate(
                        revision_prompt, coding_model, temperature=0.2
                    )
                    html_revised = clean_html(raw_html_revised)

                    # Validate revised
                    valid_rev, _ = validate_html_basic(html_revised)
                    if valid_rev:
                        html = html_revised
                    else:
                        print(
                            f"    [⚠] {method} {path}: "
                            "Revised HTML had basic issues, keeping initial."
                        )
                else:
                    print(f"    [~] {method} {path}: Critic approved.")

                # --- Security Validation (Static + LLM Critic) ---
                if (
                    vuln_spec
                    and isinstance(vuln_spec, dict)
                    and vuln_spec.get("target_route") == path
                ):
                    # 1. Static Check
                    is_valid_static, reason = verify_vulnerability_static(
                        html, vuln_spec.get("type"), vuln_spec.get("parameter")
                    )
                    if not is_valid_static:
                        print(f"    [!] {method} {path}: Static check failed: {reason}")
                        # Force a revision based on static check failure
                        sec_revision_prompt = HTML_REVISION_PROMPT.format(
                            app_name=app_name,
                            organization=organization,
                            method=method,
                            path=path,
                            page_description=info.get("description", ""),
                            site_contract="Use only the listed routes for navigation.",
                            feedback=f"SECURITY FAILURE: {reason}",
                            html=html,
                        )
                        raw_html_revised = client.generate(
                            sec_revision_prompt, coding_model, temperature=0.2
                        )
                        html = clean_html(raw_html_revised)

                    # 2. LLM Security Critic
                    print(f"    [!] {method} {path}: asking security critic...")
                    sec_critic_prompt = SECURITY_CRITIC_PROMPT.format(
                        app_name=app_name,
                        vuln_type=vuln_spec.get("type"),
                        path=path,
                        parameter=vuln_spec.get("parameter"),
                        exploit_hint=vuln_spec.get("exploit_hint"),
                        html=html,
                    )
                    sec_feedback = client.generate(
                        sec_critic_prompt, reasoning_model, temperature=0.2
                    ).strip()

                    if "SECURELY_VULNERABLE" not in sec_feedback.upper():
                        print(
                            f"    [!] {method} {path}: Security critic failed. "
                            "Revising for exploitability..."
                        )
                        sec_revision_prompt = HTML_REVISION_PROMPT.format(
                            app_name=app_name,
                            organization=organization,
                            method=method,
                            path=path,
                            page_description=info.get("description", ""),
                            site_contract="Use only the listed routes for navigation.",
                            feedback=sec_feedback,
                            html=html,
                        )
                        raw_html_revised = client.generate(
                            sec_revision_prompt, coding_model, temperature=0.2
                        )
                        html_revised = clean_html(raw_html_revised)

                        # Validate revised
                        valid_rev, _ = validate_html_basic(html_revised)
                        if valid_rev:
                            html = html_revised
                        else:
                            print(
                                f"    [⚠] {method} {path}: Security revision failed "
                                "basic validation, keeping initial."
                            )
                    else:
                        print(f"    [✓] {method} {path}: Security critic approved.")

                route_responses[path][method] = html
                print(f"    [✓] {method} {path} ({len(html)} bytes)")
                sleep(0.3)

            except Exception as e:
                print(f"    [!] Failed {method} {path}: {e}")

    # ── Step 3: Generate SSH profile ─────────────────────────────────
    print("  [3/4] Generating SSH environment profile...")
    ssh_profile = None
    try:
        ssh_prompt = SSH_PROFILE_PROMPT.format(
            context_name=ctx.context_name,
            app_name=app_name,
            domain=domain,
            organization=organization,
            country=app_country or country_hint,
            os_options=os_options_str,
        )
        raw_ssh = client.generate(ssh_prompt, coding_model, temperature=temperature)
        ssh_profile = extract_json(raw_ssh)
    except Exception as e:
        print(f"  [⚠] SSH profile generation failed: {e}")
        # Fallback SSH profile using context OS options
        ssh_profile = {
            "hostname": domain.split(".")[0] + "-prod",
            "os_version": ctx.os_options[0] if ctx.os_options else "Ubuntu 24.04 LTS",
            "kernel": "6.8.0-45-generic",
            "ssh_banner": (
                ctx.ssh_banner_options[0]
                if ctx.ssh_banner_options
                else "SSH-2.0-OpenSSH_9.6p1"
            ),
            "admin_user": "sysadmin",
            "ip_address": "10.0.1.42",
            "dns_servers": ["8.8.8.8", "8.8.4.4"],
        }

    # ── Step 4: Assemble TLS metadata ────────────────────────────────
    tls_country = app_spec.get("country", "") or ctx.tls_country or country or ""

    # ── Step 5: Save — one folder per institution ─────────────────────
    print("  [4/4] Saving...")

    # Folder name: {org_slug}_{site_id}
    org_slug = _org_slug(organization)
    folder_name = f"{org_slug}_{site_id}"
    out_dir = Path(save_path) / folder_name
    out_dir.mkdir(parents=True, exist_ok=True)

    # ── metadata.json ─────────────────────────────────────────────────
    vuln_raw = app_spec.get("vulnerability", {})
    vuln_type_str = (
        vuln_raw.get("type") if isinstance(vuln_raw, dict) else str(vuln_raw)
    )
    vuln_target = (
        vuln_raw.get("target_route") if isinstance(vuln_raw, dict) else None
    )
    vuln_param = (
        vuln_raw.get("parameter") if isinstance(vuln_raw, dict) else None
    )

    metadata = {
        "site_id": site_id,
        "model": coding_model,
        "reasoning_model": reasoning_model,
        "context": ctx.context_name,
        "country": app_country or country,
        "language": language,
        "generated_at": datetime.now().isoformat(),
        "app_name": app_spec.get("app_name", ""),
        "description": app_spec.get("description", ""),
        "organization": organization,
        "domain": domain,
        "server_profile": server_profile,
    }
    _write_json(out_dir / "metadata.json", metadata)

    # ── vulnerability.json ────────────────────────────────────────────
    vulnerability = {
        "preset": vulnerability_preset,
        "type": vuln_type_str,
        "description": vuln_raw.get("description", "") if isinstance(vuln_raw, dict) else "",
        "target_route": vuln_target,
        "parameter": vuln_param,
        "exploit_hint": vuln_raw.get("exploit_hint", "") if isinstance(vuln_raw, dict) else "",
        "is_structured": isinstance(vuln_raw, dict),
    }
    _write_json(out_dir / "vulnerability.json", vulnerability)

    # ── users.json ────────────────────────────────────────────────────
    _write_json(out_dir / "users.json", app_spec.get("users", []))

    # ── routes.json ───────────────────────────────────────────────────
    # Merge route spec (auth info, description) with generated HTML
    merged_routes = {}
    for path, info in app_spec.get("routes", {}).items():
        merged_routes[path] = {
            "methods": info.get("methods", []),
            "description": info.get("description", ""),
            "auth_required": info.get("auth_required", False),
            "page_title": info.get("page_title", ""),
            "responses": route_responses.get(path, {}),
        }
    _write_json(out_dir / "routes.json", merged_routes)

    # ── ssh_profile.json ──────────────────────────────────────────────
    _write_json(out_dir / "ssh_profile.json", ssh_profile or {})

    # ── tls.json ──────────────────────────────────────────────────────
    tls = {
        "cn": domain,
        "organization": organization,
        "country": tls_country,
        "state": "",
        "locality": "",
    }
    _write_json(out_dir / "tls.json", tls)

    # ── nuclei/ templates ─────────────────────────────────────────────
    users_list = app_spec.get("users", [])
    try:
        nuclei_files = generate_nuclei_templates(
            output_dir=out_dir,
            site_id=site_id,
            domain=domain,
            vuln_type=vuln_type_str or "generic",
            target_route=vuln_target or "/login",
            parameter=vuln_param or "input",
            users=users_list,
        )
        print(f"  [✓] Nuclei templates: {[f.name for f in nuclei_files]}")
    except Exception as e:
        print(f"  [⚠] Nuclei template generation failed: {e}")

    # ── Step 6: Verify with Nuclei ────────────────────────────────────
    try:
        from .verifier import run_verification
        run_verification(out_dir)
    except Exception as e:
        print(f"  [⚠] Nuclei verification step failed to execute: {e}")

    print(f"  [✓] Saved to folder: {folder_name}/")
    return site_id


def _write_json(path: Path, data: object) -> None:
    """Write *data* as indented JSON to *path*."""
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
