"""Multi-step honeypot site generation pipeline."""

from __future__ import annotations

import json
import os
import random
import re
import uuid
from datetime import datetime
from pathlib import Path
from time import sleep
from typing import Optional

from .clients import _generate_with_retry
from .context import DeploymentContext
from .html_tools import (
    clean_html,
    enforce_html_contract,
    extract_json,
    json_for_prompt,
    validate_html_basic,
    verify_vulnerability_static,
)
from .prompts import (
    API_SPEC_PROMPT,
    APP_SPEC_PROMPT,
    DESIGN_CRITIC_PROMPT,
    HTML_CRITIC_PROMPT,
    HTML_PAGE_PROMPT,
    HTML_REVISION_PROMPT,
    REALISM_QA_PROMPT,
    SECURITY_CRITIC_PROMPT,
    SSH_PROFILE_PROMPT,
    UX_ARCHITECT_PROMPT,
)


SERVER_PROFILES = {
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

AGENT_DEPTHS = {"basic", "standard", "deep"}


def build_context_guidance(ctx: DeploymentContext) -> str:
    """Build reusable prompt guidance from a deployment context."""
    guidance_parts = []
    if ctx.reference_organizations:
        reference_list = "\n".join(f"- {org}" for org in ctx.reference_organizations)
        guidance_parts.append(
            "Reference organizations for workflow and product inspiration only. "
            "Do not copy exact real company names, domains, logos, slogans, or "
            "trade dress unless the user supplies a custom context that explicitly "
            f"permits it:\n{reference_list}"
        )
    if ctx.prompt_guidance:
        guidance_parts.append(ctx.prompt_guidance)
    return (
        "\n\n".join(guidance_parts)
        if guidance_parts
        else "No additional context guidance."
    )


def fallback_ux_plan(app_spec: dict) -> dict:
    """Create a deterministic UX plan if the architect pass is disabled/fails."""
    route_plans = {}
    for path, info in app_spec.get("routes", {}).items():
        route_plans[path] = {
            "layout": "responsive enterprise dashboard layout",
            "primary_goal": info.get("description", info.get("page_title", path)),
            "key_content": [
                "recent activity",
                "account status",
                "role-appropriate operational data",
            ],
            "forms_or_tables": ["primary workflow form or summary table"],
            "microcopy": ["Use concise production-style labels and helper text"],
            "state_details": ["include timestamps and realistic status labels"],
            "auth_cues": ["show signed-in identity where appropriate"],
        }

    return {
        "design_system": {
            "tone": "professional and operational",
            "layout": "navigation plus content workspace",
            "visual_style": "clean enterprise web app",
            "component_patterns": ["cards", "tables", "forms", "alerts"],
            "data_density": "medium",
        },
        "navigation": [
            {
                "path": path,
                "label": info.get("page_title", path.strip("/") or "Home"),
                "priority": idx + 1,
            }
            for idx, (path, info) in enumerate(app_spec.get("routes", {}).items())
        ],
        "global_realism_details": [
            "Use plausible timestamps, IDs, account metadata, and status labels",
            "Avoid placeholders, lorem ipsum, and obviously synthetic names",
        ],
        "route_plans": route_plans,
        "quality_bar": [
            "Looks like a production portal",
            "Content fits the organization and user role",
            "All links and forms use relative paths",
        ],
    }


def build_site_contract(app_spec: dict, ux_plan: dict, contextual_routes: dict) -> str:
    """Create stable cross-page rules for the HTML generation agents."""
    nav_items = ordered_navigation_items(contextual_routes, ux_plan)
    nav_lines = "\n".join(
        f"- {item['path']}: {item['label']}" for item in nav_items
    )
    route_lines = "\n".join(f"- {path}" for path in contextual_routes)

    return f"""\
Allowed interactive route targets:
{route_lines}

Required navigation order and labels:
{nav_lines}

Layout contract:
- All authenticated application pages must use the same shell: a left sidebar
  for primary navigation, a sticky top bar for status/user controls, and a
  `.main-content` workspace. Keep class names `.sidebar`, `.top-bar`, and
  `.main-content` consistent across routes.
- Login/authentication pages (like /login) must NOT contain any navigation menu, sidebar, header links, tab bars, or list of routes. They must be completely clean and only show the login form card. Keep brand colors and typography consistent.
- Mark only the current route as active. Do not move the nav between top,
  side, and footer from page to page.
- Use responsive Bootstrap grids and table-responsive wrappers. Avoid fixed
  pixel content wider than the viewport.

Link contract:
- Every `<a href>`, `<form action>`, and `<button formaction>` must point to
  one of the allowed route targets above, an in-page section on the current
  page, or a Bootstrap/CDN asset in the document head.
- Do not invent `/profile`, `/workspace`, `/settings`, `/docs`, `/support`,
  `/logout`, or similar routes unless they are listed above. Sign-out controls
  should point to `/login`.
- Use buttons without links for visual-only actions when no route exists.

Completeness contract:
- Return a complete, valid HTML document. Close every tag you open.
- Keep tables and activity feeds compact, usually 4-6 realistic rows, so the
  response is not truncated.
"""


def ordered_navigation_items(routes: dict, ux_plan: dict) -> list[dict]:
    """Return navigation items ordered by the UX plan, with route fallbacks."""
    navigation = ux_plan.get("navigation", [])
    ordered: list[dict] = []
    seen: set[str] = set()

    if isinstance(navigation, list):
        valid_items = [
            item for item in navigation
            if isinstance(item, dict) and item.get("path") in routes
        ]
        for item in sorted(valid_items, key=lambda value: value.get("priority", 99)):
            path = item["path"]
            ordered.append({
                "path": path,
                "label": item.get(
                    "label",
                    routes[path].get("page_title", path.strip("/") or "Home"),
                ),
            })
            seen.add(path)

    for path, info in routes.items():
        if path not in seen:
            ordered.append({
                "path": path,
                "label": info.get("page_title", path.strip("/") or "Home"),
            })

    return ordered


def generate_ux_plan(client, reasoning_model: str, app_spec: dict,
                     ctx: DeploymentContext, country: str,
                     language: str, context_guidance: str,
                     temperature: float) -> dict:
    """Run the UX/product architect agent and return a plan JSON."""
    prompt = UX_ARCHITECT_PROMPT.format(
        context_name=ctx.context_name,
        app_spec_json=json_for_prompt(app_spec),
        context_guidance=context_guidance,
        country=country,
        language=language,
        offerings_label=ctx.offerings_label,
        personnel_label=ctx.personnel_label,
        dashboard_tabs=", ".join(ctx.dashboard_tabs),
    )
    raw_plan = _generate_with_retry(client, prompt, reasoning_model, temperature=temperature, max_retries=client.max_retries)
    return extract_json(raw_plan)


def get_route_plan(ux_plan: dict, path: str) -> dict:
    route_plans = ux_plan.get("route_plans", {})
    if isinstance(route_plans, dict) and isinstance(route_plans.get(path), dict):
        return route_plans[path]
    return {
        "layout": "responsive enterprise page",
        "primary_goal": path,
        "key_content": [],
        "forms_or_tables": [],
        "microcopy": [],
        "state_details": [],
        "auth_cues": [],
    }


def _org_slug(organization: str) -> str:
    """Convert an organization name to a filesystem-safe slug."""
    slug = organization.lower()
    slug = re.sub(r"[^a-z0-9]+", "_", slug)
    return slug.strip("_")[:64]


def _write_json(path: Path, data: object) -> None:
    """Write *data* as indented JSON to *path*."""
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


def _load_vulnerability_preset(preset_name: str) -> tuple[dict, str]:
    """Load a vulnerability preset JSON from generator/vulnerabilities/.

    Returns (vuln_meta dict, vuln_context string for prompt injection).
    """
    vuln_dir = Path(__file__).resolve().parents[1] / "vulnerabilities"
    vuln_path = vuln_dir / f"{preset_name}.json"
    if not vuln_path.exists():
        print(f"  [warn] Vulnerability preset '{preset_name}' not found at {vuln_path}")
        return {}, ""
    with open(vuln_path, encoding="utf-8") as f:
        meta = json.load(f)
    print(f"  [+] Using vulnerability preset: {meta.get('type')}")
    ctx_str = (
        "\nCRITICAL REQUIREMENT: The application MUST have the following "
        f"vulnerability: {meta.get('type')}.\n"
        f"Description: {meta.get('description')}\n"
        f"Target Route: {meta.get('target_route')}\n"
        f"Target Parameter: {meta.get('parameter')}\n"
        f"Exploit Hint: {meta.get('exploit_hint')}\n"
    )
    if "requirements" in meta:
        ctx_str += "Specific implementation requirements:\n"
        ctx_str += "\n".join(f"- {r}" for r in meta["requirements"])
    return meta, ctx_str


def _get_random_vulnerabilities(count_range: tuple[int, int] = (1, 3)) -> list[str]:
    vuln_dir = Path(__file__).resolve().parents[1] / "vulnerabilities"
    available = [p.stem for p in vuln_dir.glob("*.json")]
    if not available:
        return []
    count = random.randint(count_range[0], min(count_range[1], len(available)))
    return random.sample(available, count)


def generate_site(client, coding_model: str, save_path: str,
                  ctx: DeploymentContext, reasoning_model: Optional[str] = None, country: str = "",
                  language: str = "English",
                  temperature: float = 0.3,
                  agent_depth: str = "standard",
                  vulnerability_presets: Optional[list[str]] = None) -> Optional[str]:
    """Generate a complete honeypot site definition.

    Args:
        client: LLM client (OllamaClient or any HostedLLMClient).
        coding_model: Model name string.
        reasoning_model: Optional model for reasoning/critique.
        save_path: Root output directory. Each site gets its own sub-folder.
        ctx: DeploymentContext controlling org type and prompts.
        country: ISO-3166 hint, empty = LLM chooses.
        language: Natural language for UI content.
        temperature: Sampling temperature for spec / SSH generation.
        agent_depth: 'basic' | 'standard' | 'deep'.
        vulnerability_presets: List of preset names in generator/vulnerabilities/
            (e.g. ['idor', 'sql_injection']). None/empty = random selection.
    """
    agent_depth = agent_depth.lower()
    if agent_depth not in AGENT_DEPTHS:
        raise ValueError(f"agent_depth must be one of: {sorted(AGENT_DEPTHS)}")

    site_id = str(uuid.uuid4())
    if reasoning_model is None:
        reasoning_model = coding_model

    print(f"\n[*] Generating site {site_id[:8]}... "
          f"(coding={coding_model}, reasoning={reasoning_model}, context={ctx.context_name}, "
          f"country={country or 'any'}, lang={language}, "
          f"depth={agent_depth})")

    org_types_list = "\n".join(f"- {t}" for t in ctx.org_types)
    roles_list = ", ".join(ctx.user_roles)
    country_hint = country if country else "any country (your choice)"
    os_options_str = "\n".join(f"- {o}" for o in ctx.os_options)
    context_guidance = build_context_guidance(ctx)

    # ── Step 0: Load vulnerability presets ────────────────────────────
    if not vulnerability_presets:
        vulnerability_presets = _get_random_vulnerabilities()
        print(f"  [*] Randomly selected vulnerabilities: {', '.join(vulnerability_presets)}")

    vuln_metas: list[dict] = []
    vuln_contexts: list[str] = []
    for preset in vulnerability_presets:
        meta, context = _load_vulnerability_preset(preset)
        if meta:
            vuln_metas.append(meta)
            vuln_contexts.append(context)

    combined_vuln_context = "\n".join(vuln_contexts)

    # ── Step 1: App specification ─────────────────────────────────────
    print("  [1/8] Generating app specification...")
    try:
        spec_prompt = APP_SPEC_PROMPT.format(
            context_name=ctx.context_name,
            org_types_list=org_types_list,
            country_hint=country_hint,
            name_style=ctx.name_style,
            language=language,
            context_guidance=context_guidance,
            roles_list=roles_list,
        )
        if combined_vuln_context:
            spec_prompt += f"\n{combined_vuln_context}"
        raw_spec = _generate_with_retry(client, spec_prompt, coding_model, temperature=temperature, max_retries=client.max_retries)
        app_spec = extract_json(raw_spec)
    except Exception as e:
        print(f"  [error] Failed to generate app spec: {e}")
        return None

    app_name = app_spec.get("app_name", f"{ctx.context_name.title()} Portal")
    organization = app_spec.get("organization", "Example Organization")
    domain = app_spec.get("domain", "portal.example.org")
    app_country = app_spec.get("country", country or "")
    server_profile = app_spec.get("server_profile", "apache_2_4")
    if server_profile not in SERVER_PROFILES:
        server_profile = "apache_2_4"

    print(f"  [ok] App: {app_name} | Org: {organization} | "
          f"Profile: {server_profile} | Domain: {domain}")

    # ── Step 2: UX Architect agent ────────────────────────────────────
    ux_plan = fallback_ux_plan(app_spec)
    if agent_depth in {"standard", "deep"}:
        print("  [2/8] UX architect agent planning realism details...")
        try:
            ux_plan = generate_ux_plan(
                client=client,
                reasoning_model=reasoning_model,
                app_spec=app_spec,
                ctx=ctx,
                country=app_country or country_hint,
                language=language,
                context_guidance=context_guidance,
                temperature=temperature,
            )
            print("  [ok] UX plan generated")
        except Exception as e:
            print(f"  [warn] UX architect failed, using fallback plan: {e}")
    else:
        print("  [2/8] UX architect agent skipped (agent_depth=basic)")

    # ── Step 3: HTML pages ────────────────────────────────────────────
    print("  [3/8] Generating HTML pages...")
    route_responses = generate_route_pages(
        client=client,
        coding_model=coding_model,
        reasoning_model=reasoning_model,
        ctx=ctx,
        app_spec=app_spec,
        app_name=app_name,
        organization=organization,
        country_hint=country_hint,
        app_country=app_country,
        language=language,
        ux_plan=ux_plan,
        context_guidance=context_guidance,
        agent_depth=agent_depth,
        vuln_metas=vuln_metas,
    )
    missing_pages = find_missing_route_pages(app_spec, route_responses)
    if missing_pages:
        print(
            "  [error] Site generation aborted; missing valid HTML for: "
            f"{', '.join(missing_pages)}"
        )
        return None

    # ── Step 4: API endpoint data ─────────────────────────────────────
    print("  [4/8] Generating REST API endpoint data...")
    api_routes_data = generate_api_routes(
        client=client,
        coding_model=coding_model,
        app_spec=app_spec,
        app_name=app_name,
        organization=organization,
        domain=domain,
        country=app_country or country_hint,
        language=language,
        temperature=temperature,
    )

    # ── Step 5: SSH profile ───────────────────────────────────────────
    print("  [5/6] Generating SSH environment profile...")
    ssh_profile = generate_ssh_profile(
        client=client,
        coding_model=coding_model,
        ctx=ctx,
        app_name=app_name,
        domain=domain,
        organization=organization,
        country=app_country or country_hint,
        os_options_str=os_options_str,
        temperature=temperature,
    )

    tls_country = app_spec.get("country", "") or ctx.tls_country or country or ""

    # ── Step 6: Save — modular folder per site ────────────────────────
    print("  [6/6] Saving...")
    org_slug = _org_slug(organization)
    folder_name = f"{org_slug}_{site_id}"
    out_dir = Path(save_path) / folder_name
    out_dir.mkdir(parents=True, exist_ok=True)

    # metadata.json
    _write_json(out_dir / "metadata.json", {
        "site_id": site_id,
        "model": coding_model,
        "reasoning_model": reasoning_model,
        "context": ctx.context_name,
        "country": app_country or country,
        "language": language,
        "agent_depth": agent_depth,
        "generated_at": datetime.now().isoformat(),
        "app_name": app_spec.get("app_name", ""),
        "description": app_spec.get("description", ""),
        "organization": organization,
        "domain": domain,
        "server_profile": server_profile
    })

    # vulnerabilities.json
    output_vulns = []
    
    # Try to parse LLM's returned vulnerabilities array, fallback to our generated one
    llm_vulns = app_spec.get("vulnerabilities", [])
    if isinstance(llm_vulns, list) and llm_vulns:
        output_vulns = llm_vulns
    else:
        for preset, meta in zip(vulnerability_presets, vuln_metas):
            output_vulns.append({
                "preset": preset,
                "type": meta.get("type"),
                "description": meta.get("description"),
                "target_route": meta.get("target_route"),
                "parameter": meta.get("parameter"),
                "exploit_hint": meta.get("exploit_hint"),
                "is_structured": True
            })
            
    _write_json(out_dir / "vulnerabilities.json", output_vulns)

    # users.json
    users_list = app_spec.get("users", [])
    users_list.extend([
        {"username": "admin", "password": "password", "role": "admin", "display_name": "Administrator", "email": "admin@example.com"},
        {"username": "admin", "password": "admin", "role": "admin", "display_name": "Administrator", "email": "admin@example.com"},
        {"username": "root", "password": "root", "role": "admin", "display_name": "Root Admin", "email": "root@example.com"},
        {"username": "guest", "password": "guest", "role": "user", "display_name": "Guest User", "email": "guest@example.com"},
        {"username": "test", "password": "test", "role": "user", "display_name": "Test User", "email": "test@example.com"}
    ])
    _write_json(out_dir / "users.json", users_list)

    # routes.json  (route spec + generated HTML merged)
    merged_routes = {}
    for path, info in app_spec.get("routes", {}).items():
        merged_routes[path] = {
            "methods": info.get("methods", []),
            "description": info.get("description", ""),
            "auth_required": False,
            "page_title": info.get("page_title", ""),
            "responses": route_responses.get(path, {}),
        }
        
    # INJECT WORDPRESS LURE
    merged_routes["/wp-login.php"] = {
        "methods": ["GET", "POST"],
        "description": "WordPress Login",
        "auth_required": False,
        "page_title": "WordPress Log In",
        "responses": {
            "GET": "<!DOCTYPE html><html><head><title>WordPress &rsaquo; Log In</title></head><body><form name='loginform' id='loginform' action='/wp-login.php' method='post'><p><label for='user_login'>Username</label><br /><input type='text' name='log' id='user_login' class='input' value='' size='20' /></p><p><label for='user_pass'>Password</label><br /><input type='password' name='pwd' id='user_pass' class='input' value='' size='20' /></p><p><input type='submit' name='wp-submit' id='wp-submit' class='button button-primary button-large' value='Log In' /></p></form></body></html>",
            "POST": "<!DOCTYPE html><html><head><title>WordPress &rsaquo; Error</title></head><body><div id='login_error'><strong>ERROR</strong>: The password you entered for the username is incorrect.</div></body></html>"
        }
    }

    # INJECT ENTERPRISE LURES
    merged_routes["/phpmyadmin/"] = {
        "methods": ["GET", "POST"],
        "description": "phpMyAdmin Login",
        "auth_required": False,
        "page_title": "phpMyAdmin",
        "responses": {
            "GET": "<!DOCTYPE html><html><head><title>phpMyAdmin</title></head><body><form method='post' action='index.php'><label>Username: <input type='text' name='pma_username'></label><br><label>Password: <input type='password' name='pma_password'></label><br><input type='submit' value='Go'></form></body></html>",
            "POST": "<!DOCTYPE html><html><head><title>phpMyAdmin</title></head><body>Access denied for user.</body></html>"
        }
    }
    
    merged_routes["/manager/html"] = {
        "methods": ["GET"],
        "description": "Tomcat Manager",
        "auth_required": False,
        "page_title": "Tomcat Web Application Manager",
        "responses": {
            "GET": "<html><head><title>401 Unauthorized</title></head><body><h1>401 Unauthorized</h1><p>You are not authorized to view this page.</p></body></html>"
        }
    }
    
    merged_routes["/owa/auth/logon.aspx"] = {
        "methods": ["GET", "POST"],
        "description": "Outlook Web Access",
        "auth_required": False,
        "page_title": "Outlook",
        "responses": {
            "GET": "<html><head><title>Outlook</title></head><body><form action='/owa/auth.owa' method='POST'><input type='text' name='username'><input type='password' name='password'><input type='submit' value='Sign In'></form></body></html>",
            "POST": "<html><head><title>Outlook</title></head><body>The username or password you entered isn't correct. Try entering it again.</body></html>"
        }
    }
        
    _write_json(out_dir / "routes.json", merged_routes)

    # ssh_profile.json
    _write_json(out_dir / "ssh_profile.json", ssh_profile or {})

    # tls.json
    _write_json(out_dir / "tls.json", {
        "cn": domain,
        "organization": organization,
        "country": tls_country,
        "state": "",
        "locality": "",
    })

    # ux_plan.json (new — from agent depth standard/deep)
    _write_json(out_dir / "ux_plan.json", ux_plan)

    # api_routes.json
    # INJECT IDOR VULNERABLE API
    api_routes_data["/api/v1/users/{id}"] = {
        "auth_required": False,
        "idor_enabled": True,
        "user_responses": {
            "1": {"id": 1, "username": "admin", "role": "admin"},
            "2": {"id": 2, "username": "guest", "role": "user"}
        }
    }
    _write_json(out_dir / "api_routes.json", api_routes_data)


    # ── Step 7: Nuclei templates + verification ───────────────────────
    print("  [7/7] Generating Nuclei templates...")
    users_list = app_spec.get("users", [])
    try:
        from ..nuclei_utils import generate_nuclei_templates
        nuclei_files = generate_nuclei_templates(
            output_dir=out_dir,
            site_id=site_id,
            domain=domain,
            vulnerabilities=output_vulns,
            users=users_list,
        )
        print(f"  [ok] Nuclei templates: {[f.name for f in nuclei_files]}")
    except Exception as e:
        print(f"  [warn] Nuclei template generation failed: {e}")

    try:
        from ..verifier import run_verification
        run_verification(out_dir)
    except Exception as e:
        print(f"  [warn] Nuclei verification step failed: {e}")

    print(f"  [ok] Saved to folder: {folder_name}/")
    return site_id


def generate_route_pages(client, coding_model: str, reasoning_model: str, ctx: DeploymentContext,
                         app_spec: dict, app_name: str, organization: str,
                         country_hint: str, app_country: str, language: str,
                         ux_plan: dict, context_guidance: str,
                         agent_depth: str,
                         vuln_metas: list[dict] = None) -> dict:
    if vuln_metas is None:
        vuln_metas = []
    route_responses: dict = {}
    routes = app_spec.get("routes", {})
    allowed_routes = list(routes.keys())

    brand_color_line, brand_color_instruction = build_brand_prompt(ctx)
    logo_line = (
        f"Logo URL: {ctx.logo_url}"
        if ctx.logo_url
        else "Logo: use a text-based logo or leave it as the organization name"
    )
    ux_plan_prompt = json_for_prompt(ux_plan)
    first_auth_page_html = None

    for path, info in routes.items():
        route_responses[path] = {}
        page_title = info.get("page_title", info.get("description", app_name))
        route_plan_prompt = json_for_prompt(get_route_plan(ux_plan, path))
        
        # Build contextual routes based on authentication state
        is_secure = info.get("auth_required", False)
        contextual_routes = {
            p: r_info for p, r_info in routes.items() 
            if r_info.get("auth_required", False) == is_secure
        }
        
        nav_routes = ", ".join(
            f"{p} ({r_info.get('page_title', r_info.get('description', 'Page'))})"
            for p, r_info in contextual_routes.items()
        )
        site_contract = build_site_contract(app_spec, ux_plan, contextual_routes)

        for method in info.get("methods", ["GET"]):
            user_state = user_state_for_route(app_spec, info)
            
            previous_page_context = ""
            if is_secure and first_auth_page_html:
                previous_page_context = (
                    "═══════════════════════════════════════════════════════════════════════\n"
                    "CONSISTENCY REQUIREMENT (CRITICAL)\n"
                    "═══════════════════════════════════════════════════════════════════════\n"
                    "To ensure perfect consistency across the application, you MUST reuse the EXACT SAME "
                    "navigation sidebar, top bar, layout structure, and <style> block from this previously generated page:\n\n"
                    f"```html\n{first_auth_page_html}\n```\n\n"
                    "DO NOT change the sidebar structure, the logo layout, or the CSS variables. "
                    "Only replace the `.main-content` area to fit this current route's purpose."
                )

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
                context_guidance=context_guidance,
                ux_plan=ux_plan_prompt,
                route_plan=route_plan_prompt,
                site_contract=site_contract,
                brand_color_instruction=brand_color_instruction,
                context_name=ctx.context_name,
                language=language,
                previous_page_context=previous_page_context,
                users_json=json_for_prompt(app_spec.get("users", [])),
                offerings_label=ctx.offerings_label,
                personnel_label=ctx.personnel_label,
                dashboard_persona=ctx.dashboard_persona,
                dashboard_tabs=", ".join(ctx.dashboard_tabs),
            )

            try:
                html = clean_html(_generate_with_retry(client, prompt, coding_model, temperature=0.2, max_retries=client.max_retries))
                html = apply_html_contract(
                    html,
                    allowed_routes=allowed_routes,
                    path=path,
                    method=method,
                )
                if agent_depth != "basic":
                    html = repair_with_critic(
                        client=client,
                        coding_model=coding_model,
                        reasoning_model=reasoning_model,
                        html=html,
                        app_name=app_name,
                        organization=organization,
                        method=method,
                        path=path,
                        page_description=info.get("description", ""),
                        language=language,
                        site_contract=site_contract,
                        allowed_routes=allowed_routes,
                        offerings_label=ctx.offerings_label,
                        personnel_label=ctx.personnel_label,
                        dashboard_tabs=", ".join(ctx.dashboard_tabs),
                    )

                    html = design_critic_pass(
                        client=client,
                        coding_model=coding_model,
                        reasoning_model=reasoning_model,
                        html=html,
                        app_name=app_name,
                        organization=organization,
                        method=method,
                        path=path,
                        page_description=info.get("description", ""),
                        site_contract=site_contract,
                        allowed_routes=allowed_routes,
                    )

                if agent_depth == "deep":
                    html = realism_qa(
                        client=client,
                        coding_model=coding_model,
                        reasoning_model=reasoning_model,
                        html=html,
                        app_name=app_name,
                        organization=organization,
                        context_name=ctx.context_name,
                        method=method,
                        path=path,
                        page_description=info.get("description", ""),
                        route_plan=route_plan_prompt,
                        site_contract=site_contract,
                        allowed_routes=allowed_routes,
                    )

                # Security critic: check all vulnerabilities assigned to this route
                if agent_depth != "basic":
                    for v_meta in vuln_metas:
                        if v_meta.get("target_route") == path:
                            html = security_critic_pass(
                                client=client,
                                coding_model=coding_model,
                                reasoning_model=reasoning_model,
                                html=html,
                                app_name=app_name,
                                organization=organization,
                                method=method,
                                path=path,
                                page_description=info.get("description", ""),
                                site_contract=site_contract,
                                allowed_routes=allowed_routes,
                                vuln_meta=v_meta,
                            )

                html = apply_html_contract(
                    html,
                    allowed_routes=allowed_routes,
                    path=path,
                    method=method,
                )
                
                if is_secure and not first_auth_page_html:
                    first_auth_page_html = html

                route_responses[path][method] = html
                print(f"    [ok] {method} {path} ({len(html)} bytes)")
                sleep(0.3)
            except Exception as e:
                print(f"    [error] Failed {method} {path}: {e}")

    return route_responses


def find_missing_route_pages(app_spec: dict, route_responses: dict) -> list[str]:
    missing = []
    for path, info in app_spec.get("routes", {}).items():
        generated_methods = route_responses.get(path, {})
        for method in info.get("methods", ["GET"]):
            if not generated_methods.get(method):
                missing.append(f"{method} {path}")
    return missing


def build_brand_prompt(ctx: DeploymentContext) -> tuple[str, str]:
    if ctx.brand_color:
        return (
            f"Primary brand color: {ctx.brand_color}",
            f"Use the brand color {ctx.brand_color} for headers, buttons, "
            "and accents",
        )
    return (
        "Primary brand color: pick a professional color appropriate "
        "for the organization",
        "Choose a professional brand color appropriate for the organization "
        "type. Use it consistently for headers, buttons, and accents",
    )


def user_state_for_route(app_spec: dict, route_info: dict) -> str:
    if not route_info.get("auth_required", False):
        return "Not authenticated (anonymous visitor)"

    users = app_spec.get("users", [])
    user = next((u for u in users if u.get("role") != "admin"),
                users[0] if users else {})
    return (
        f"Logged in as {user.get('display_name', 'User')} "
        f"({user.get('role', 'user')}, {user.get('email', '')})"
    )


def apply_html_contract(html: str, allowed_routes: list[str],
                        path: str, method: str) -> str:
    html, repairs = enforce_html_contract(
        html,
        allowed_routes=allowed_routes,
        current_path=path,
    )
    for repair in repairs:
        print(f"    [fix] {method} {path}: {repair}")
    return html


def security_critic_pass(client, coding_model: str, reasoning_model: str, html: str, app_name: str,
                         organization: str, method: str, path: str,
                         page_description: str, site_contract: str,
                         allowed_routes: list[str], vuln_meta: dict) -> str:
    """Run static check + LLM security critic to ensure the vulnerability is real."""
    vuln_type = vuln_meta.get("type", "")
    parameter = vuln_meta.get("parameter", "")
    exploit_hint = vuln_meta.get("exploit_hint", "")

    # 1. Static pre-check
    is_ok, reason = verify_vulnerability_static(html, vuln_type, parameter)
    if not is_ok:
        print(f"    [sec] {method} {path}: static check failed — {reason}. Forcing revision.")
        html = clean_html(_generate_with_retry(client,
            HTML_REVISION_PROMPT.format(
                app_name=app_name,
                organization=organization,
                method=method,
                path=path,
                page_description=page_description,
                site_contract=site_contract,
                feedback=f"SECURITY FAILURE: {reason}",
                html=html,
            ),
            coding_model,
            temperature=0.2,
            max_retries=client.max_retries,
        ))
        html = apply_html_contract(html, allowed_routes, path, method)

    # 2. LLM security critic
    print(f"    [sec] {method} {path}: security critic")
    sec_feedback = _generate_with_retry(client,
        SECURITY_CRITIC_PROMPT.format(
            app_name=app_name,
            vuln_type=vuln_type,
            path=path,
            parameter=parameter,
            exploit_hint=exploit_hint,
            html=html,
        ),
        reasoning_model,
        temperature=0.2,
        max_retries=client.max_retries,
    ).strip()

    if "SECURELY_VULNERABLE" in sec_feedback.upper():
        print(f"    [sec] {method} {path}: security critic approved")
        return html

    print(f"    [sec] {method} {path}: security critic requested revision")
    revised = clean_html(_generate_with_retry(client,
        HTML_REVISION_PROMPT.format(
            app_name=app_name,
            organization=organization,
            method=method,
            path=path,
            page_description=page_description,
            site_contract=site_contract,
            feedback=sec_feedback,
            html=html,
        ),
        coding_model,
        temperature=0.2,
        max_retries=client.max_retries,
    ))
    revised = apply_html_contract(revised, allowed_routes, path, method)
    valid_rev, _ = validate_html_basic(revised)
    if valid_rev:
        return revised
    print(f"    [warn] {method} {path}: security revision failed validation, keeping prior")
    return html


def design_critic_pass(client, coding_model: str, reasoning_model: str, html: str, app_name: str,
                       organization: str, method: str, path: str,
                       page_description: str, site_contract: str,
                       allowed_routes: list[str]) -> str:
    print(f"    [agent] {method} {path}: design critic")
    critic_prompt = DESIGN_CRITIC_PROMPT.format(
        app_name=app_name,
        organization=organization,
        method=method,
        path=path,
        page_description=page_description,
        site_contract=site_contract,
        html=html,
    )
    critic_feedback = _generate_with_retry(client,
        critic_prompt,
        reasoning_model,
        temperature=0.2,
        max_retries=client.max_retries,
    ).strip()

    if "APPROVED" in critic_feedback.upper():
        print(f"    [agent] {method} {path}: design critic approved")
        return html

    print(f"    [agent] {method} {path}: design critic requested revision")
    revised = clean_html(_generate_with_retry(client,
        HTML_REVISION_PROMPT.format(
            app_name=app_name,
            organization=organization,
            method=method,
            path=path,
            page_description=page_description,
            site_contract=site_contract,
            feedback=critic_feedback,
            html=html,
        ),
        coding_model,
        temperature=0.2,
        max_retries=client.max_retries,
    ))
    revised = apply_html_contract(
        revised,
        allowed_routes=allowed_routes,
        path=path,
        method=method,
    )
    valid_revised, issues_revised = validate_html_basic(revised)
    if valid_revised:
        return revised

    print(f"    [warn] {method} {path}: design revision had basic issues "
          f"({', '.join(issues_revised)}), keeping prior version")
    return html


def repair_with_critic(client, coding_model: str, reasoning_model: str, html: str, app_name: str,
                       organization: str, method: str, path: str,
                       page_description: str, language: str,
                       site_contract: str, allowed_routes: list[str],
                       offerings_label: str, personnel_label: str, dashboard_tabs: str) -> str:
    valid, issues = validate_html_basic(html)
    if not valid:
        print(f"    [warn] {method} {path}: {', '.join(issues)}; "
              "attempting cleanup")
        html = clean_html(html)
        valid, issues = validate_html_basic(html)

    if valid:
        print(f"    [agent] {method} {path}: critic")
        critic_prompt = HTML_CRITIC_PROMPT.format(
            app_name=app_name,
            organization=organization,
            method=method,
            path=path,
            page_description=page_description,
            site_contract=site_contract,
            language=language,
            html=html,
            offerings_label=offerings_label,
            personnel_label=personnel_label,
            dashboard_tabs=dashboard_tabs,
        )
        critic_feedback = _generate_with_retry(client,
            critic_prompt,
            reasoning_model,
            temperature=0.2,
            max_retries=client.max_retries,
        ).strip()
    else:
        print(f"    [agent] {method} {path}: critic forced revision")
        critic_feedback = (
            "Fix these HTML validity issues before any other change: "
            f"{', '.join(issues)}. Return a complete compact document that "
            "obeys the site-wide HTML contract."
        )

    if "APPROVED" in critic_feedback.upper():
        print(f"    [agent] {method} {path}: critic approved")
        return html

    print(f"    [agent] {method} {path}: critic requested revision")
    revised = clean_html(_generate_with_retry(client,
        HTML_REVISION_PROMPT.format(
            app_name=app_name,
            organization=organization,
            method=method,
            path=path,
            page_description=page_description,
            site_contract=site_contract,
            feedback=critic_feedback,
            html=html,
        ),
        coding_model,
        temperature=0.2,
        max_retries=client.max_retries,
    ))
    revised = apply_html_contract(
        revised,
        allowed_routes=allowed_routes,
        path=path,
        method=method,
    )
    valid_revised, issues_revised = validate_html_basic(revised)
    if valid_revised:
        return revised

    print(f"    [warn] {method} {path}: revised HTML had basic issues "
          f"({', '.join(issues_revised)})")
    valid_initial, issues_initial = validate_html_basic(html)
    if valid_initial:
        print(f"    [warn] {method} {path}: keeping valid initial HTML")
        return html

    raise ValueError(
        "Unable to produce valid HTML after revision: "
        f"{', '.join(issues_revised or issues_initial)}"
    )


def realism_qa(client, coding_model: str, reasoning_model: str, html: str, app_name: str,
               organization: str, context_name: str, method: str, path: str,
               page_description: str, route_plan: str,
               site_contract: str, allowed_routes: list[str]) -> str:
    print(f"    [agent] {method} {path}: realism QA")
    qa_prompt = REALISM_QA_PROMPT.format(
        app_name=app_name,
        organization=organization,
        context_name=context_name,
        method=method,
        path=path,
        page_description=page_description,
        site_contract=site_contract,
        route_plan=route_plan,
        html=html,
    )
    qa_feedback = _generate_with_retry(client, qa_prompt, reasoning_model, temperature=0.2, max_retries=client.max_retries).strip()
    if "APPROVED" in qa_feedback.upper():
        print(f"    [agent] {method} {path}: realism QA approved")
        return html

    print(f"    [agent] {method} {path}: realism QA requested revision")
    revised = clean_html(_generate_with_retry(client,
        HTML_REVISION_PROMPT.format(
            app_name=app_name,
            organization=organization,
            method=method,
            path=path,
            page_description=page_description,
            site_contract=site_contract,
            feedback=qa_feedback,
            html=html,
        ),
        coding_model,
        temperature=0.2,
        max_retries=client.max_retries,
    ))
    revised = apply_html_contract(
        revised,
        allowed_routes=allowed_routes,
        path=path,
        method=method,
    )
    valid_revised, issues_revised = validate_html_basic(revised)
    if valid_revised:
        return revised

    print(f"    [warn] {method} {path}: QA revision had basic issues "
          f"({', '.join(issues_revised)}), keeping prior version")
    return html


def generate_ssh_profile(client, coding_model: str, ctx: DeploymentContext,
                         app_name: str, domain: str, organization: str,
                         country: str, os_options_str: str,
                         temperature: float) -> dict:
    try:
        ssh_prompt = SSH_PROFILE_PROMPT.format(
            context_name=ctx.context_name,
            app_name=app_name,
            domain=domain,
            organization=organization,
            country=country,
            os_options=os_options_str,
        )
        raw_ssh = _generate_with_retry(client, ssh_prompt, coding_model, temperature=temperature, max_retries=client.max_retries)
        return extract_json(raw_ssh)
    except Exception as e:
        print(f"  [warn] SSH profile generation failed: {e}")
        return {
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


def generate_api_routes(client, coding_model: str, app_spec: dict,
                        app_name: str, organization: str, domain: str,
                        country: str, language: str,
                        temperature: float) -> dict:
    """Generate realistic JSON API endpoint response data.

    Returns a dict mapping API route paths to their response definitions,
    including per-user IDOR data for endpoints that support ID parameters.
    """
    api_routes_spec = app_spec.get("api_routes", {})
    if not api_routes_spec:
        print("  [warn] No api_routes in app spec, generating defaults")
        api_routes_spec = {
            "/api/v1/users": {
                "methods": ["GET"],
                "description": "List all users",
                "auth_required": True,
                "supports_id_param": False,
            },
            "/api/v1/users/{id}": {
                "methods": ["GET"],
                "description": "Get user details by ID",
                "auth_required": True,
                "supports_id_param": True,
            },
        }

    try:
        prompt = API_SPEC_PROMPT.format(
            app_name=app_name,
            organization=organization,
            domain=domain,
            country=country,
            language=language,
            users_json=json_for_prompt(app_spec.get("users", [])),
            api_routes_json=json_for_prompt(api_routes_spec),
        )
        raw = _generate_with_retry(client, prompt, coding_model, temperature=temperature, max_retries=client.max_retries)
        api_data = extract_json(raw)
        route_count = len(api_data) if isinstance(api_data, dict) else 0
        print(f"  [ok] Generated {route_count} API endpoints")
        return api_data
    except Exception as e:
        print(f"  [warn] API route generation failed: {e}")
        # Return a minimal fallback
        users = app_spec.get("users", [])
        user_list = []
        user_responses = {}
        import random
        from datetime import datetime
        for u in users:
            uid = u.get("data", {}).get("user_id", len(user_list) + 1)
            user_list.append({
                "id": uid,
                "username": u.get("username", ""),
                "role": u.get("role", ""),
                "email": u.get("email", ""),
                "status": "active",
                "last_login": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
            })
            user_responses[str(uid)] = {
                "id": uid,
                "username": u.get("username", ""),
                "display_name": u.get("display_name", ""),
                "email": u.get("email", ""),
                "role": u.get("role", ""),
                "status": "active",
                "department": u.get("data", {}).get("department", "General"),
                "created_at": "2023-01-15T08:30:00Z",
                "last_login": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
                "phone": f"+{random.randint(10000000000, 99999999999)}",
                "internal_notes": "User account is in good standing.",
            }
        return {
            "/api/v1/users": {
                "methods": ["GET"],
                "auth_required": True,
                "content_type": "application/json",
                "response": {
                    "status": "success",
                    "data": user_list,
                    "pagination": {
                        "page": 1,
                        "per_page": 20,
                        "total": len(user_list),
                    },
                },
            },
            "/api/v1/users/{id}": {
                "methods": ["GET"],
                "auth_required": True,
                "content_type": "application/json",
                "idor_enabled": True,
                "user_responses": user_responses,
            },
        }
