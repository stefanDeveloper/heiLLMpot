"""
Generic honeypot site generator.

Generates high-quality fake web application sites using LLMs via Ollama.
Deployable anywhere in the world with configurable context (university,
hospital, bank, government, corporate, or a custom JSON context).

Improvements over the original:
  - Fully configurable deployment context (no Heidelberg/Germany hardcoding)
  - OllamaClient class with retry logic and configurable endpoint
  - DeploymentContext dataclass controls prompts, naming, OS, and SSH banners
  - CLI: --context, --country, --language, --temperature, --ollama-url
  - Post-processing: HTML validation, placeholder removal, broken tag repair
  - Generates both authenticated and unauthenticated versions of each page
  - Generates error pages (404, 403, 500) per site
  - Includes server fingerprint metadata in the output
  - Generates SSH environment profile (filesystem, users, services) per site
"""

import os
import uuid
import json
import re
import time
import random
import argparse
from dataclasses import dataclass, field
from html.parser import HTMLParser
from datetime import datetime
from time import sleep
from typing import Optional
from pathlib import Path

import requests
from tqdm import tqdm


# ─── Deployment context ────────────────────────────────────────────────────────

@dataclass
class DeploymentContext:
    """All the parameters that control how site content is generated."""

    context_name: str = "university"
    org_types: list = field(default_factory=lambda: [
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
    user_roles: list = field(default_factory=lambda: [
        "admin", "student", "professor", "staff"
    ])
    # How to describe what kinds of names/users should appear
    name_style: str = "international, appropriate for the specified country"
    # Brand color injected into HTML prompt; empty = let LLM decide
    brand_color: str = ""
    # Logo URL to show in nav bar; empty = LLM picks a plausible placeholder
    logo_url: str = ""
    # OS options the SSH profile can pick from
    os_options: list = field(default_factory=lambda: [
        "Ubuntu 24.04 LTS",
        "Ubuntu 22.04 LTS",
        "Debian 12 (Bookworm)",
    ])
    # SSH banner strings matching the OS options
    ssh_banner_options: list = field(default_factory=lambda: [
        "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5",
        "SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u3",
        "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10",
    ])
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


# ─── Server profiles ──────────────────────────────────────────────────────────

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


# ─── Ollama client ────────────────────────────────────────────────────────────

class OllamaClient:
    """Thin client for the Ollama /api/generate endpoint with retry logic."""

    def __init__(self, base_url: str = "http://localhost:11434",
                 timeout: int = 300, max_retries: int = 3):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.max_retries = max_retries

    @property
    def generate_url(self) -> str:
        return f"{self.base_url}/api/generate"

    def generate(self, prompt: str, model: str,
                 temperature: float = 0.3) -> str:
        """Call Ollama generate API and return response text.

        Retries up to `max_retries` times on transient errors with
        exponential back-off.
        """
        payload = {
            "model": model,
            "prompt": prompt,
            "stream": False,
            "options": {"temperature": temperature},
        }
        last_error: Optional[Exception] = None
        for attempt in range(self.max_retries):
            try:
                res = requests.post(
                    self.generate_url,
                    json=payload,
                    timeout=self.timeout,
                )
                res.raise_for_status()
                return res.json()["response"]
            except (requests.ConnectionError, requests.Timeout) as e:
                last_error = e
                wait = 2 ** attempt + random.uniform(0, 1)
                print(f"    [retry {attempt + 1}/{self.max_retries}] "
                      f"Connection error: {e}. Retrying in {wait:.1f}s...")
                time.sleep(wait)
            except requests.HTTPError as e:
                # Non-retriable HTTP errors (e.g. 404 model not found)
                raise
        raise RuntimeError(
            f"Ollama request failed after {self.max_retries} retries: {last_error}"
        )

    def list_models(self) -> list[str]:
        """Return list of available model names from Ollama."""
        try:
            res = requests.get(f"{self.base_url}/api/tags", timeout=10)
            res.raise_for_status()
            return [m["name"] for m in res.json().get("models", [])]
        except Exception:
            return []


# ─── Prompt templates ────────────────────────────────────────────────────────
#
# All locale-specific values are injected via format() — nothing hardcoded.

APP_SPEC_PROMPT = """\
Generate a detailed specification for a realistic fake web application that \
belongs to a {context_name} organization.

Choose ONE application type from this list:
{org_types_list}

Country / region: {country_hint}
User name style: {name_style}
Language for UI text and content: {language}

Requirements:
1. The app MUST feel authentic — use realistic page titles, form fields, and \
navigation appropriate for a {context_name}
2. Create at least 3-5 distinct users with realistic names, emails, and roles \
for the specified country/language. Roles: {roles_list}
3. Each user should have role-specific data (e.g., a doctor has patient \
appointments, a student has enrolled courses)
4. Routes must include at minimum: /, /login, plus 3-5 app-specific routes
5. Include a "vulnerability" field describing one intentional weakness (SQL \
injection, XSS, IDOR, path traversal, etc.)

Output strict JSON with this schema:
{{
  "app_name": "string",
  "description": "string",
  "server_profile": "one of: apache_2_4, nginx_1_24, iis_10, tomcat_9",
  "organization": "string (e.g., Springfield General Hospital)",
  "domain": "string (e.g., portal.springfield-hospital.org)",
  "country": "string (ISO 3166-1 alpha-2, e.g. US, DE, FR)",
  "vulnerability": "string describing the intentional vulnerability",
  "users": [
    {{
      "username": "string",
      "password": "string",
      "role": "string",
      "display_name": "string",
      "email": "string",
      "data": {{}}
    }}
  ],
  "routes": {{
    "/path": {{
      "methods": ["GET", "POST"],
      "description": "string",
      "auth_required": true,
      "page_title": "string"
    }}
  }}
}}

Respond ONLY with JSON. No markdown, no explanation.
"""

HTML_PAGE_PROMPT = """\
You are generating the HTML page body for a web application.

Application: {app_name}
Organization: {organization}
Country / locale: {country}
Page: {method} {path} — {page_description}
Page Title: {page_title}
Current User: {user_state}
App routes for navigation: {nav_routes}
{brand_color_line}
{logo_line}

Requirements:
1. Output a COMPLETE, valid HTML5 document (<!DOCTYPE html> through </html>)
2. Use Bootstrap 5 CDN for styling
3. Include a proper <head> with <meta charset>, <title>, viewport meta
4. Include a navigation bar with the organization name, app name, and links \
to all routes
5. {brand_color_instruction}
6. For login pages: include a proper form with username/password fields and a \
submit button
7. For authenticated pages: show the current user's name and a logout link
8. Make it look like a REAL {context_name} web portal — professional, clean, \
functional
9. Do NOT use template syntax like {{{{ }}}} or Jinja placeholders
10. Do NOT include any HTTP headers, just the HTML document
11. Use realistic content in {language} — real-looking data, not "Lorem ipsum"
12. All form actions should use relative paths (e.g., action="/login")

Output ONLY the HTML document. No markdown fences, no explanation, no \
comments outside HTML.
"""

HTML_CRITIC_PROMPT = """\
You are an expert web developer reviewing an HTML page for a honeypot web application.

Application: {app_name}
Organization: {organization}
Page: {method} {path} — {page_description}

Review the following HTML for:
1. Realism and Professionalism
2. Consistency (Brand colors, Logo, Navigation bar)
3. HTML5 Validity
4. Bootstrap 5 layout usage
5. Realistic content in {language}

If the HTML is excellent and needs no changes, output exactly the word "APPROVED".
Otherwise, provide a concise list of instructions on how to improve the HTML to make it more realistic and professional.
DO NOT output the corrected HTML, only the critique instructions.

HTML to review:
{html}
"""

HTML_REVISION_PROMPT = """\
You are an expert web developer. You previously generated an HTML page for this application, but a reviewer provided feedback for improvements.

Application: {app_name}
Organization: {organization}
Page: {method} {path} — {page_description}

Here is the reviewer's feedback:
{feedback}

Here is your previous HTML:
{html}

Please provide the FULL, revised HTML document incorporating the feedback. Ensure it is a completely valid HTML5 document. Choose styling that looks realistic and professional.
Output ONLY the HTML document. No markdown fences, no explanation, no comments outside HTML.
"""

SSH_PROFILE_PROMPT = """\
Generate a realistic SSH server environment profile for a Linux server \
running a {context_name} web application called "{app_name}".

Organization: {organization}
Domain: {domain}
Country: {country}
Operating system (choose one): {os_options}

Output strict JSON matching this schema:
{{
  "hostname": "string (realistic short hostname, e.g. web01, mail-gw, \
portal-prod)",
  "os_version": "string (full OS name matching your choice above)",
  "kernel": "string (realistic kernel version for the chosen OS)",
  "ssh_banner": "string (realistic SSH banner for the chosen OS)",
  "ip_address": "string (private or institutional IP, e.g. 10.0.1.42 or \
192.168.10.5)",
  "dns_servers": ["string", "..."],
  "dns_search": "{domain}",
  "admin_user": "string (realistic sysadmin username for the country/org)",
  "admin_groups": ["sudo", "www-data", "adm"],
  "services": ["sshd", "apache2 or nginx", "mysql or postgresql"],
  "cron_jobs": ["0 2 * * * /usr/local/bin/backup.sh", "0 4 * * 0 certbot renew"],
  "installed_packages": ["list of realistic packages for the chosen OS"],
  "motd_extra_lines": [
    "System information as of ...",
    "System load:  0.08",
    "Memory usage: 28%"
  ],
  "recent_auth_log_entries": [
    "Accepted publickey for <admin_user> from <some_ip> port 52341"
  ]
}}

Respond ONLY with JSON.
"""


# ─── Helper functions ─────────────────────────────────────────────────────────

def remove_think_tags(text: str) -> str:
    """Remove <think>...</think> blocks from reasoning models."""
    return re.sub(r"<think>.*?</think>", "", text, flags=re.DOTALL).strip()


def extract_json(text: str) -> dict:
    """Extract JSON from LLM output, handling markdown fences."""
    text = remove_think_tags(text)

    # Try to find JSON in markdown code fence
    match = re.search(r"```(?:json)?\s*(.*?)```", text, re.DOTALL)
    if match:
        text = match.group(1).strip()

    # Try to find the outermost { ... }
    start = text.find("{")
    end = text.rfind("}")
    if start != -1 and end != -1 and end > start:
        text = text[start : end + 1]

    return json.loads(text)


def clean_html(html: str) -> str:
    """Post-process HTML output from LLMs to fix common issues."""
    # Remove markdown code fences
    html = re.sub(r"```(?:html)?\s*\n?", "", html)
    html = html.strip()

    # Remove <think>...</think> blocks
    html = remove_think_tags(html)

    # Remove LLM template placeholders: {{ anything }}
    html = re.sub(r"\{\{\s*[\w.]+\s*\}\}", "", html)

    # Remove Jinja-style {% %} blocks
    html = re.sub(r"\{%.*?%\}", "", html, flags=re.DOTALL)

    # Fix common broken tags from small LLMs
    html = re.sub(r"<(title|div|span|p|h[1-6])\.", r"<\1>", html)

    # Fix <j Doctype html> or similar
    html = re.sub(r"<j\s+Doctype\s+html>", "<!DOCTYPE html>", html,
                  flags=re.IGNORECASE)

    # Remove HTTP headers that leaked into HTML body
    if html.startswith("HTTP/"):
        parts = html.split("\n\n", 1)
        if len(parts) == 2:
            html = parts[1]

    # Replace localhost URLs
    html = re.sub(r"http://localhost:\d+", "", html)
    html = re.sub(r"http://127\.0\.0\.1:\d+", "", html)

    # Ensure DOCTYPE is present
    if not html.strip().lower().startswith("<!doctype"):
        if "<html" in html.lower():
            html = "<!DOCTYPE html>\n" + html
        else:
            html = (
                "<!DOCTYPE html>\n<html><head><title>Page</title></head>"
                f"<body>\n{html}\n</body></html>"
            )

    # Ensure closing tags
    for tag in ["</html>", "</body>"]:
        if tag not in html.lower():
            if tag == "</html>":
                html += "\n</html>"
            elif tag == "</body>":
                html = html.replace("</html>", "</body>\n</html>")

    return html


def validate_html_basic(html: str) -> tuple[bool, list[str]]:
    """Basic HTML validation — check for common issues."""
    issues = []

    if "<!DOCTYPE" not in html and "<!doctype" not in html:
        issues.append("Missing DOCTYPE")
    if "<html" not in html.lower():
        issues.append("Missing <html> tag")
    if "<head" not in html.lower():
        issues.append("Missing <head> tag")
    if "<body" not in html.lower():
        issues.append("Missing <body> tag")
    if "{{" in html and "}}" in html:
        issues.append("Contains template placeholders")
    if "```" in html:
        issues.append("Contains markdown fences")

    return len(issues) == 0, issues


# ─── Site generation ──────────────────────────────────────────────────────────

def generate_site(client: OllamaClient, model: str, save_path: str,
                  ctx: DeploymentContext, country: str = "",
                  language: str = "English",
                  temperature: float = 0.3) -> Optional[str]:
    """Generate a complete honeypot site definition.

    Args:
        client: OllamaClient instance
        model: Ollama model name
        save_path: directory to write the output JSON
        ctx: DeploymentContext controlling what kind of org is simulated
        country: ISO-3166 country code hint (e.g. "US", "DE") or "" for any
        language: Natural language for UI content (e.g. "English", "German")
        temperature: LLM temperature for generation

    Returns:
        site_id string on success, None on failure
    """
    site_id = str(uuid.uuid4())
    print(f"\n[*] Generating site {site_id[:8]}... "
          f"(model={model}, context={ctx.context_name}, "
          f"country={country or 'any'}, lang={language})")

    # Build prompt-friendly strings from context lists
    org_types_list = "\n".join(f"- {t}" for t in ctx.org_types)
    roles_list = ", ".join(ctx.user_roles)
    country_hint = country if country else "any country (your choice)"
    os_options_str = "\n".join(f"- {o}" for o in ctx.os_options)

    # ── Step 1: Generate app spec ────────────────────────────────────
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
        raw_spec = client.generate(spec_prompt, model, temperature=temperature)
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

    print(f"  [✓] App: {app_name} | Org: {organization} | "
          f"Profile: {server_profile} | Domain: {domain}")

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
            f"Use the brand color {ctx.brand_color} for headers, buttons, "
            "and accents"
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
                    users[0] if users else {}
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
                brand_color_instruction=brand_color_instruction,
                context_name=ctx.context_name,
                language=language,
            )

            try:
                raw_html = client.generate(prompt, model, temperature=0.2)
                html = clean_html(raw_html)

                # Validate and attempt repair on second pass
                valid, issues = validate_html_basic(html)
                if not valid:
                    print(f"    [⚠] {method} {path}: "
                          f"{', '.join(issues)} — attempting repair")
                    html = clean_html(html)

                # --- Critic Loop ---
                print(f"    [~] {method} {path}: asking critic...")
                critic_prompt = HTML_CRITIC_PROMPT.format(
                    app_name=app_name,
                    organization=organization,
                    method=method,
                    path=path,
                    page_description=info.get("description", ""),
                    language=language,
                    html=html
                )
                critic_feedback = client.generate(critic_prompt, model, temperature=0.2).strip()
                
                if "APPROVED" not in critic_feedback.upper():
                    print(f"    [~] {method} {path}: Critic suggested improvements. Revising...")
                    revision_prompt = HTML_REVISION_PROMPT.format(
                        app_name=app_name,
                        organization=organization,
                        method=method,
                        path=path,
                        page_description=info.get("description", ""),
                        feedback=critic_feedback,
                        html=html
                    )
                    raw_html_revised = client.generate(revision_prompt, model, temperature=0.2)
                    html_revised = clean_html(raw_html_revised)
                    
                    # Validate revised
                    valid_rev, issues_rev = validate_html_basic(html_revised)
                    if valid_rev:
                        html = html_revised
                    else:
                        print(f"    [⚠] {method} {path}: Revised HTML had basic issues, keeping initial.")
                else:
                    print(f"    [~] {method} {path}: Critic approved.")

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
        raw_ssh = client.generate(ssh_prompt, model, temperature=temperature)
        ssh_profile = extract_json(raw_ssh)
    except Exception as e:
        print(f"  [⚠] SSH profile generation failed: {e}")
        # Fallback SSH profile using context OS options
        ssh_profile = {
            "hostname": domain.split(".")[0] + "-prod",
            "os_version": ctx.os_options[0] if ctx.os_options else "Ubuntu 24.04 LTS",
            "kernel": "6.8.0-45-generic",
            "ssh_banner": (ctx.ssh_banner_options[0]
                           if ctx.ssh_banner_options
                           else "SSH-2.0-OpenSSH_9.6p1"),
            "admin_user": "sysadmin",
            "ip_address": "10.0.1.42",
            "dns_servers": ["8.8.8.8", "8.8.4.4"],
        }

    # ── Step 4: Assemble TLS metadata ────────────────────────────────
    # Determine TLS country from spec > context > CLI arg > empty
    tls_country = (
        app_spec.get("country", "")
        or ctx.tls_country
        or country
        or ""
    )

    # ── Step 5: Save ─────────────────────────────────────────────────
    print("  [4/4] Saving...")
    data = {
        "site_id": site_id,
        "model": model,
        "context": ctx.context_name,
        "country": app_country or country,
        "language": language,
        "generated_at": datetime.now().isoformat(),
        "app_spec": app_spec,
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

    print(f"  [✓] Saved: {filename}")
    return site_id


# ─── Main ─────────────────────────────────────────────────────────────────────

def build_context(context_arg: str) -> DeploymentContext:
    """Resolve --context argument to a DeploymentContext."""
    # If it looks like a file path, load it directly
    if context_arg.endswith(".json") or os.path.sep in context_arg:
        if not os.path.exists(context_arg):
            raise FileNotFoundError(
                f"Context file not found: {context_arg}"
            )
        return DeploymentContext.from_json(context_arg)

    # Otherwise treat as a built-in preset name
    return DeploymentContext.builtin(context_arg)


def main():
    parser = argparse.ArgumentParser(
        description="Generate honeypot site definitions using an Ollama LLM.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Generate 3 hospital sites in the US using llama3.2:3b
  %(prog)s --models llama3.2:3b --count 3 --context hospital \\
            --country US --language English

  # Generate university sites in German
  %(prog)s --models llama3.2:3b --count 5 --context university \\
            --country DE --language German

  # Use a custom context file
  %(prog)s --models llama3.2:3b --count 2 \\
            --context llm_ctf/contexts/custom.json

  # Use a remote Ollama instance
  %(prog)s --models llama3.3:70b --count 10 \\
            --ollama-url http://192.168.1.100:11434
        """,
    )
    parser.add_argument(
        "--models",
        nargs="+",
        default=["llama3.2:3b"],
        help="Ollama model names to use (space-separated)",
    )
    parser.add_argument(
        "--count",
        type=int,
        default=5,
        help="Number of sites to generate per model (default: 5)",
    )
    parser.add_argument(
        "--output",
        type=str,
        default="./generated_sites",
        help="Output directory for generated site JSON files",
    )
    parser.add_argument(
        "--context",
        type=str,
        default="university",
        help=(
            "Deployment context: built-in name (university, hospital, bank, "
            "corporate, government) or path to a custom context .json file"
        ),
    )
    parser.add_argument(
        "--country",
        type=str,
        default="",
        help=(
            "ISO 3166-1 alpha-2 country code for localization "
            "(e.g. US, DE, FR, JP). Leave empty to let the LLM decide."
        ),
    )
    parser.add_argument(
        "--language",
        type=str,
        default="English",
        help="Natural language for generated UI content (default: English)",
    )
    parser.add_argument(
        "--temperature",
        type=float,
        default=0.3,
        help="LLM sampling temperature for spec/SSH generation (default: 0.3)",
    )
    # Ollama endpoint — two names, same dest
    endpoint_group = parser.add_mutually_exclusive_group()
    endpoint_group.add_argument(
        "--ollama-url",
        dest="ollama_url",
        type=str,
        default="http://localhost:11434",
        help="Ollama server base URL (default: http://localhost:11434)",
    )
    endpoint_group.add_argument(
        "--endpoint",
        dest="ollama_url",
        type=str,
        help="Alias for --ollama-url (backward compatibility)",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=300,
        help="HTTP request timeout for Ollama calls in seconds (default: 300)",
    )
    parser.add_argument(
        "--retries",
        type=int,
        default=3,
        help="Max retries on transient Ollama errors (default: 3)",
    )
    parser.add_argument(
        "--list-models",
        action="store_true",
        help="List available models from the Ollama server and exit",
    )

    args = parser.parse_args()

    # Build Ollama client
    client = OllamaClient(
        base_url=args.ollama_url,
        timeout=args.timeout,
        max_retries=args.retries,
    )

    # --list-models shortcut
    if args.list_models:
        models = client.list_models()
        if models:
            print("Available models:")
            for m in models:
                print(f"  {m}")
        else:
            print("Could not retrieve model list from Ollama.")
        return

    # Resolve deployment context
    try:
        ctx = build_context(args.context)
    except (ValueError, FileNotFoundError) as e:
        print(f"[!] {e}")
        return

    print(f"[*] Context: {ctx.context_name}")
    print(f"[*] Country: {args.country or '(any)'}")
    print(f"[*] Language: {args.language}")
    print(f"[*] Ollama URL: {args.ollama_url}")
    print(f"[*] Temperature: {args.temperature}")
    print(f"[*] Models: {', '.join(args.models)}")

    os.makedirs(args.output, exist_ok=True)

    total = len(args.models) * args.count
    generated = 0
    failed = 0

    for model in args.models:
        print(f"\n{'='*60}")
        print(f"Model: {model}")
        print(f"{'='*60}")

        for i in tqdm(range(args.count), desc=model):
            result = generate_site(
                client=client,
                model=model,
                save_path=args.output,
                ctx=ctx,
                country=args.country,
                language=args.language,
                temperature=args.temperature,
            )
            if result:
                generated += 1
            else:
                failed += 1

    print(f"\n{'='*60}")
    print(f"Done! Generated: {generated}, Failed: {failed}, Total: {total}")
    print(f"Output: {args.output}")


if __name__ == "__main__":
    main()
