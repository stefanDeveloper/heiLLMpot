"""Prompt templates for the multi-agent site generation pipeline."""

APP_SPEC_PROMPT = """\
Generate a detailed specification for a realistic fake web application that \
belongs to a {context_name} organization.

Choose ONE application type from this list:
{org_types_list}

Country / region: {country_hint}
User name style: {name_style}
Language for UI text and content: {language}

Context guidance:
{context_guidance}

Requirements:
1. The app MUST feel authentic. Use realistic page titles, form fields, and \
navigation appropriate for a {context_name}
2. Create at least 3-5 distinct users with realistic names, emails, and roles \
for the specified country/language. Roles: {roles_list}
3. Each user should have role-specific data (for example, a doctor has patient \
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


UX_ARCHITECT_PROMPT = """\
You are the UX/product architect agent for a defensive honeypot site generator.
Create a realism plan for a fictional {context_name} web application.

Application spec JSON:
{app_spec_json}

Context guidance:
{context_guidance}

Country / locale: {country}
Language for UI text and content: {language}

Your job:
1. Define an information architecture and navigation model.
2. Define a professional visual system that is believable for the sector.
3. For each route, specify realistic modules, tables, forms, empty states,
   admin notices, timestamps, metrics, account details, and microcopy.
4. Include plausible operational details that make the portal feel alive.
5. Keep all organizations, domains, logos, and slogans fictional.

Output strict JSON with this schema:
{{
  "design_system": {{
    "tone": "string",
    "layout": "string",
    "visual_style": "string",
    "component_patterns": ["string"],
    "data_density": "low|medium|high"
  }},
  "navigation": [
    {{"path": "/path", "label": "string", "priority": 1}}
  ],
  "global_realism_details": ["string"],
  "route_plans": {{
    "/path": {{
      "layout": "string",
      "primary_goal": "string",
      "key_content": ["string"],
      "forms_or_tables": ["string"],
      "microcopy": ["string"],
      "state_details": ["string"],
      "auth_cues": ["string"]
    }}
  }},
  "quality_bar": ["string"]
}}

Respond ONLY with JSON. No markdown, no explanation.
"""


HTML_PAGE_PROMPT = """\
You are generating the HTML page body for a web application.

Application: {app_name}
Organization: {organization}
Country / locale: {country}
Page: {method} {path} - {page_description}
Page Title: {page_title}
Current User: {user_state}
App routes for navigation: {nav_routes}
{brand_color_line}
{logo_line}
{context_guidance}
UX / product architecture plan:
{ux_plan}
Route-specific realism plan:
{route_plan}
Site-wide HTML contract:
{site_contract}

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
8. Make it look like a REAL {context_name} web portal: professional, clean, \
functional
9. Do NOT use template syntax like {{{{ }}}} or Jinja placeholders
10. Do NOT include any HTTP headers, just the HTML document
11. Use realistic content in {language}; real-looking data, not "Lorem ipsum"
12. All form actions should use relative paths (e.g., action="/login")
13. Keep the page compact enough to finish in one response: 4-6 realistic rows
    per table and no oversized inline datasets
14. Never invent navigation targets outside the site-wide contract

Output ONLY the HTML document. No markdown fences, no explanation, no comments \
outside HTML.
"""


HTML_CRITIC_PROMPT = """\
You are an expert web developer reviewing an HTML page for a honeypot web \
application.

Application: {app_name}
Organization: {organization}
Page: {method} {path} - {page_description}
Site-wide HTML contract:
{site_contract}

Review the following HTML for:
1. Realism and Professionalism
2. Consistency (Brand colors, Logo, Navigation bar)
3. HTML5 Validity
4. Bootstrap 5 layout usage
5. Realistic content in {language}
6. No dead links, invented routes, dangling tags, or route-to-route layout drift

If the HTML is excellent and needs no changes, output exactly the word \
"APPROVED".
Otherwise, provide a concise list of instructions on how to improve the HTML to \
make it more realistic and professional.
DO NOT output the corrected HTML, only the critique instructions.

HTML to review:
{html}
"""


REALISM_QA_PROMPT = """\
You are the final realism QA agent for a defensive honeypot website generator.

Application: {app_name}
Organization: {organization}
Context: {context_name}
Route: {method} {path} - {page_description}
Site-wide HTML contract:
{site_contract}
Route plan:
{route_plan}

Review the HTML for:
1. Believable sector-specific workflow and terminology
2. Realistic account, security, billing, operational, or admin details
3. Professional production-web-app polish, not a generic template
4. Consistency with the route plan and navigation
5. No real-brand impersonation, real logos, real domains, or placeholder text
6. No dead links, invented routes, dangling tags, or route-to-route layout drift

If the page is excellent, output exactly "APPROVED".
Otherwise, provide concise revision instructions. Do not output HTML.

HTML to review:
{html}
"""


HTML_REVISION_PROMPT = """\
You are an expert web developer. You previously generated an HTML page for this \
application, but a reviewer provided feedback for improvements.

Application: {app_name}
Organization: {organization}
Page: {method} {path} - {page_description}
Site-wide HTML contract:
{site_contract}

Here is the reviewer's feedback:
{feedback}

Here is your previous HTML:
{html}

Please provide the FULL, revised HTML document incorporating the feedback. \
Ensure it is a completely valid HTML5 document. Choose styling that looks \
realistic and professional. Keep it compact enough to finish in one response \
and obey the site-wide HTML contract exactly.
Output ONLY the HTML document. No markdown fences, no explanation, no comments \
outside HTML.
"""


SSH_PROFILE_PROMPT = """\
Generate a realistic SSH server environment profile for a Linux server running \
a {context_name} web application called "{app_name}".

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


SECURITY_CRITIC_PROMPT = """\
You are a Penetration Tester reviewing an HTML page for a honeypot application.

Application: {app_name}
Target Vulnerability: {vuln_type}
Intended Location: {path} (parameter: {parameter})

Review the following HTML to verify if the vulnerability is REAL, EXPLOITABLE, \
and DETECTABLE by an automated scanner such as Nuclei.

Requirements for Approval:
1. The vulnerable parameter MUST be present in a form or JS script.
2. There MUST be a clear lack of sanitization or a logic flaw that allows the \
exploit hint to work: {exploit_hint}
3. The page must NOT have security headers or meta-tags that accidentally \
mitigate the vulnerability (e.g., a strict CSP that blocks inline scripts for \
XSS, or X-Frame-Options that breaks clickjacking).
4. For SQLi: the form must submit to the backend in a way that would trigger a \
visible error or behavior change.
5. For IDOR: the parameter must be present in the URL/form and the response \
must contain user-specific data.
6. For LFI/Path Traversal: the file parameter must be unfiltered and the \
content must be reflected.
7. For Open Redirect: the redirect parameter must be followed without origin \
validation.

If the vulnerability is perfectly implemented, output exactly the word \
"SECURELY_VULNERABLE".
Otherwise, provide a concise list of security-specific instructions on how to \
make the vulnerability actually exploitable.

HTML to review:
{html}
"""

