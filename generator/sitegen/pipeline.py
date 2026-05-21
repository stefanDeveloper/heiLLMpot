"""Multi-step honeypot site generation pipeline."""

from __future__ import annotations

import json
import os
import uuid
from datetime import datetime
from time import sleep
from typing import Optional

from .context import DeploymentContext
from .html_tools import (
    clean_html,
    enforce_html_contract,
    extract_json,
    json_for_prompt,
    validate_html_basic,
)
from .prompts import (
    APP_SPEC_PROMPT,
    HTML_CRITIC_PROMPT,
    HTML_PAGE_PROMPT,
    HTML_REVISION_PROMPT,
    REALISM_QA_PROMPT,
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


def build_site_contract(app_spec: dict, ux_plan: dict) -> str:
    """Create stable cross-page rules for the HTML generation agents."""
    routes = app_spec.get("routes", {})
    nav_items = ordered_navigation_items(routes, ux_plan)
    nav_lines = "\n".join(
        f"- {item['path']}: {item['label']}" for item in nav_items
    )
    route_lines = "\n".join(f"- {path}" for path in routes)

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
- Login/authentication pages may use a centered auth card, but must keep the
  same brand colors, typography, and route list.
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


def generate_ux_plan(client, model: str, app_spec: dict,
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
    )
    raw_plan = client.generate(prompt, model, temperature=temperature)
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


def generate_site(client, model: str, save_path: str,
                  ctx: DeploymentContext, country: str = "",
                  language: str = "English",
                  temperature: float = 0.3,
                  agent_depth: str = "standard") -> Optional[str]:
    """Generate a complete honeypot site definition."""
    agent_depth = agent_depth.lower()
    if agent_depth not in AGENT_DEPTHS:
        raise ValueError(f"agent_depth must be one of: {sorted(AGENT_DEPTHS)}")

    site_id = str(uuid.uuid4())
    print(f"\n[*] Generating site {site_id[:8]}... "
          f"(model={model}, context={ctx.context_name}, "
          f"country={country or 'any'}, lang={language})")

    org_types_list = "\n".join(f"- {t}" for t in ctx.org_types)
    roles_list = ", ".join(ctx.user_roles)
    country_hint = country if country else "any country (your choice)"
    os_options_str = "\n".join(f"- {o}" for o in ctx.os_options)
    context_guidance = build_context_guidance(ctx)

    print("  [1/5] Generating app specification...")
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
        raw_spec = client.generate(spec_prompt, model, temperature=temperature)
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

    ux_plan = fallback_ux_plan(app_spec)
    if agent_depth in {"standard", "deep"}:
        print("  [2/5] UX architect agent planning realism details...")
        try:
            ux_plan = generate_ux_plan(
                client=client,
                model=model,
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
        print("  [2/5] UX architect agent skipped (agent_depth=basic)")

    print("  [3/5] Generating HTML pages...")
    route_responses = generate_route_pages(
        client=client,
        model=model,
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
    )
    missing_pages = find_missing_route_pages(app_spec, route_responses)
    if missing_pages:
        print(
            "  [error] Site generation aborted; missing valid HTML for: "
            f"{', '.join(missing_pages)}"
        )
        return None

    print("  [4/5] Generating SSH environment profile...")
    ssh_profile = generate_ssh_profile(
        client=client,
        model=model,
        ctx=ctx,
        app_name=app_name,
        domain=domain,
        organization=organization,
        country=app_country or country_hint,
        os_options_str=os_options_str,
        temperature=temperature,
    )

    tls_country = app_spec.get("country", "") or ctx.tls_country or country or ""

    print("  [5/5] Saving...")
    data = {
        "site_id": site_id,
        "model": model,
        "context": ctx.context_name,
        "country": app_country or country,
        "language": language,
        "agent_depth": agent_depth,
        "generated_at": datetime.now().isoformat(),
        "app_spec": app_spec,
        "ux_plan": ux_plan,
        "server_profile": server_profile,
        "ssh_profile": ssh_profile,
        "tls": {
            "cn": domain,
            "organization": organization,
            "country": tls_country,
            "state": "",
            "locality": "",
        },
        "routes": route_responses,
    }

    filename = f"{model.replace(':', '_')}_{site_id}.json"
    filepath = os.path.join(save_path, filename)
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

    print(f"  [ok] Saved: {filename}")
    return site_id


def generate_route_pages(client, model: str, ctx: DeploymentContext,
                         app_spec: dict, app_name: str, organization: str,
                         country_hint: str, app_country: str, language: str,
                         ux_plan: dict, context_guidance: str,
                         agent_depth: str) -> dict:
    route_responses: dict = {}
    routes = app_spec.get("routes", {})
    allowed_routes = list(routes.keys())
    nav_routes = ", ".join(
        f"{path} ({info.get('page_title', info.get('description', 'Page'))})"
        for path, info in routes.items()
    )
    site_contract = build_site_contract(app_spec, ux_plan)

    brand_color_line, brand_color_instruction = build_brand_prompt(ctx)
    logo_line = (
        f"Logo URL: {ctx.logo_url}"
        if ctx.logo_url
        else "Logo: use a text-based logo or leave it as the organization name"
    )
    ux_plan_prompt = json_for_prompt(ux_plan)

    for path, info in routes.items():
        route_responses[path] = {}
        page_title = info.get("page_title", info.get("description", app_name))
        route_plan_prompt = json_for_prompt(get_route_plan(ux_plan, path))

        for method in info.get("methods", ["GET"]):
            user_state = user_state_for_route(app_spec, info)
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
            )

            try:
                html = clean_html(client.generate(prompt, model, temperature=0.2))
                html = apply_html_contract(
                    html,
                    allowed_routes=allowed_routes,
                    path=path,
                    method=method,
                )
                html = repair_with_critic(
                    client=client,
                    model=model,
                    html=html,
                    app_name=app_name,
                    organization=organization,
                    method=method,
                    path=path,
                    page_description=info.get("description", ""),
                    language=language,
                    site_contract=site_contract,
                    allowed_routes=allowed_routes,
                )

                if agent_depth == "deep":
                    html = realism_qa(
                        client=client,
                        model=model,
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

                html = apply_html_contract(
                    html,
                    allowed_routes=allowed_routes,
                    path=path,
                    method=method,
                )
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


def repair_with_critic(client, model: str, html: str, app_name: str,
                       organization: str, method: str, path: str,
                       page_description: str, language: str,
                       site_contract: str, allowed_routes: list[str]) -> str:
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
        )
        critic_feedback = client.generate(
            critic_prompt,
            model,
            temperature=0.2,
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
    revised = clean_html(client.generate(
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
        model,
        temperature=0.2,
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


def realism_qa(client, model: str, html: str, app_name: str,
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
    qa_feedback = client.generate(qa_prompt, model, temperature=0.2).strip()
    if "APPROVED" in qa_feedback.upper():
        print(f"    [agent] {method} {path}: realism QA approved")
        return html

    print(f"    [agent] {method} {path}: realism QA requested revision")
    revised = clean_html(client.generate(
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
        model,
        temperature=0.2,
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


def generate_ssh_profile(client, model: str, ctx: DeploymentContext,
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
        raw_ssh = client.generate(ssh_prompt, model, temperature=temperature)
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
