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
for the specified country/language. To ensure the generated dashboard is consistent, \
all non-admin users MUST be of a single cohesive persona appropriate for the \
{context_name} (e.g., all students, or all employees). Use roles from: {roles_list}
3. Each user should have role-specific data (for example, a doctor has patient \
appointments, a student has enrolled courses)
4. Routes must include at minimum: /, /login, plus 3-5 app-specific routes
5. Each user MUST have a sequential integer "user_id" in their "data" object \
(starting from 1). This is used by the backend for record lookup.
6. Include 2-4 REST API route paths in the "api_routes" section. These are \
backend JSON endpoints that a real application would expose (e.g., \
/api/v1/users, /api/v1/records). At least one endpoint MUST support fetching \
a single resource by numeric ID (e.g., /api/v1/users/{{id}}).

Output strict JSON with this schema:
{{
  "app_name": "string",
  "description": "string",
  "server_profile": "one of: apache_2_4, nginx_1_24, iis_10, tomcat_9",
  "organization": "string (e.g., Springfield General Hospital)",
  "domain": "string (e.g., portal.springfield-hospital.org)",
  "country": "string (ISO 3166-1 alpha-2, e.g. US, DE, FR)",
  "users": [
    {{
      "username": "string",
      "password": "string",
      "role": "string",
      "display_name": "string",
      "email": "string",
      "data": {{"user_id": 1}}
    }}
  ],
  "routes": {{
    "/path": {{
      "methods": ["GET", "POST"],
      "description": "string",
      "auth_required": true,
      "page_title": "string"
    }}
  }},
  "api_routes": {{
    "/api/v1/resource": {{
      "methods": ["GET"],
      "description": "string",
      "auth_required": true,
      "supports_id_param": false
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
4. CRITICAL: For the public landing page (/ or /home), your plan MUST specify a 2-tab layout: one tab for {offerings_label} and one tab for {personnel_label} (a directory of users).
5. CRITICAL: For the primary authenticated dashboard, your plan MUST specify a 3-tab layout using these exact tabs: {dashboard_tabs}.
6. Include plausible operational details that make the portal feel alive.
7. Keep all organizations, domains, logos, and slogans fictional.

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
You are generating a production-grade HTML page for a realistic web application \
used as a defensive honeypot. The page MUST look indistinguishable from a real \
enterprise portal.

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
{previous_page_context}

Users in the system (for personnel directory):
{users_json}

═══════════════════════════════════════════════════════════════════════
CORE REQUIREMENTS
═══════════════════════════════════════════════════════════════════════

1. Output a COMPLETE, valid HTML5 document (<!DOCTYPE html> through </html>).
2. Include a proper <head> with <meta charset>, <title>, viewport meta, and \
   Bootstrap 5 CDN (CSS + JS bundle).
3. Use Google Fonts (e.g., Inter, Roboto, or Source Sans Pro) for typography.

═══════════════════════════════════════════════════════════════════════
MULTI-PAGE NAVIGATION (CRITICAL)
═══════════════════════════════════════════════════════════════════════

4. Build a CONTEXTUAL navigation shell based on the provided app routes:
   - For public pages (like the root landing page / or /home): Create a highly engaging, visually impressive landing page that perfectly matches the {context_name} theme and {organization} context. 
     CRITICAL: The main content of the landing page MUST be organized into exactly 2 tabs (using Bootstrap nav-tabs or pills):
       1. '{offerings_label}': A tab showcasing the organization's core offerings.
       2. '{personnel_label}': A directory tab listing all non-admin users from the system. For each user, you MUST display their display name, role/title, department, and explicitly show their 'Username: [username]' as a visible detail (e.g. Email: user@org, Username: user).
     Include a prominent "Login" or "Sign In" button/link that points directly to `/login`. Do not include authenticated navigation links.
   - For authenticated pages: Build a fixed left sidebar (250px) with the organization logo/name at top,
     followed by navigation links for EVERY route listed in the app routes.
     Include a sticky top bar with the current page title and user identity/logout.
     CRITICAL: The main content area of the primary dashboard/workspace MUST include a tabbed interface with exactly 3 functional tabs: {dashboard_tabs}. The content must reflect the {dashboard_persona} persona.
   - For login pages (/login): Do NOT include the sidebar, topbar, tab bars, headers, or any navigation
     links/menus. The login screen must be isolated and only show the credentials card.
5. EVERY navigation link MUST use a real <a href="/route"> pointing to one \
   of the allowed routes. The current page's link must be visually highlighted \
   (active state with accent color).
6. DO NOT add any navigation items that are not in the allowed routes list! \
   No "About", "Services", "Contact", "Help", "Settings", "Profile" unless \
   they are explicitly listed in the routes.
7. The sidebar must use consistent class names: .sidebar, .sidebar-nav, \
   .sidebar-link, .sidebar-link.active. The topbar: .top-bar. The content: \
   .main-content.

═══════════════════════════════════════════════════════════════════════
VISUAL DESIGN & REALISM (PREMIUM QUALITY)
═══════════════════════════════════════════════════════════════════════

8.  {brand_color_instruction}. Use it for: sidebar background or accent, \
    active nav items, primary buttons, and key headings.
9.  Login page layout (/login):
    - Hide ALL sidebars, menus, header links, and navigation tabs.
    - Centered card layout with the organization logo, username + password fields, a prominent "Sign In" button, and a subtle footer.
    - Include a dark, modern, or gradient background behind the card. Keep it clean and completely focused on the login form.
10. Dashboard/authenticated pages MUST show highly realistic, sector-appropriate enterprise content:
    - Summary cards/widgets with metrics (e.g., "Active Tasks: 1,247", "Sync Status: Healthy", "Last Update: 2 mins ago")
    - Rich data tables with 4-6 realistic rows (names, IDs, timestamps, statuses).
    - Table column formatting is CRITICAL: Ensure columns are properly aligned, header text matches data type, dates/currencies are properly formatted, and status values use colored badges (green/amber/red pills).
    - Activity feeds, system alerts, or recent operation logs.
11. Professional CSS styling to look like a modern SaaS portal (not simple HTML):
    - Card components with rounded corners (border-radius: 8-12px) and subtle box-shadows.
    - Hover effects with smooth transitions (0.2s ease).
    - Sidebar with a dark/branded background, clean contrast, white text, and hover states.
    - Balanced spacing (paddings, margins) and responsive tables (table-responsive).
12. Every page must include a <style> block with custom CSS variables for brand colors to ensure absolute visual consistency.
    - MUST define and use these exact variables: `--primary-color`, `--surface-color`, `--text-muted`.

═══════════════════════════════════════════════════════════════════════
GOLDEN EXAMPLE (DASHBOARD WIDGET / TABLE)
═══════════════════════════════════════════════════════════════════════
Use this HTML structure as inspiration for your components to ensure premium quality:
```html
<div class="card shadow-sm border-0 mb-4" style="border-radius: 10px;">
  <div class="card-header bg-white border-bottom-0 pt-4 pb-0">
    <h5 class="mb-0 fw-bold" style="color: var(--primary-color);">Recent Activity</h5>
  </div>
  <div class="card-body">
    <div class="table-responsive">
      <table class="table table-hover align-middle mb-0">
        <thead class="text-muted" style="font-size: 0.85rem; text-transform: uppercase;">
          <tr>
            <th>ID</th>
            <th>Description</th>
            <th class="text-end">Status</th>
          </tr>
        </thead>
        <tbody>
          <tr>
            <td class="fw-medium">#REQ-992</td>
            <td>System synchronization</td>
            <td class="text-end"><span class="badge bg-success rounded-pill">Active</span></td>
          </tr>
        </tbody>
      </table>
    </div>
  </div>
</div>
```

═══════════════════════════════════════════════════════════════════════
CONTENT & REALISM
═══════════════════════════════════════════════════════════════════════

13. Use realistic content in {language}: real-looking data, names appropriate \
    for the country, plausible dates, IDs, and status labels. Never use \
    "Lorem ipsum", "John Doe", "test@example.com", or obvious placeholder text.
14. For login pages: You MUST use standard HTML form submission without JavaScript interception. Use <form action="/login" method="POST"> with input fields named "username" and "password". Do NOT include an MFA token field, verification code input, or any multi-factor authentication fields on the login page. The server handles MFA on a separate page. Do NOT use fetch() or e.preventDefault() for the login form. Let the server handle the redirect natively.
15. For authenticated pages: show the logged-in user's display name in the \
    topbar with a "Sign Out" link pointing to /login.
16. All form actions must use relative paths (e.g., action="/login").
17. Keep the page compact enough to finish in one response: 4-6 rows per table, \
    no oversized inline datasets.
18. Do NOT use template syntax like {{{{ }}}} or Jinja placeholders.
19. Do NOT include any HTTP headers, just the HTML document.
20. Never invent navigation targets outside the site-wide contract.

Output ONLY the HTML document. No markdown fences, no explanation, no comments \
outside HTML.
"""


HTML_CRITIC_PROMPT = """\
You are a senior web developer and UX expert reviewing an HTML page for a \
honeypot web application that must fool real attackers.

Application: {app_name}
Organization: {organization}
Page: {method} {path} - {page_description}
Site-wide HTML contract:
{site_contract}

Review the following HTML for these critical criteria:

1. **Multi-page navigation**: Does the page respect the contextual navigation shell specified \
   in the site contract? Are class names consistent (.sidebar, .top-bar, \
   .main-content) for authenticated pages? Is the current route marked active? \
   CRITICAL: If the route is /login, does it completely HIDE any sidebar, topbar, tab bars, header links, and nav menus? \
   CRITICAL: If this is a public landing page (/, /home), does the main content have exactly 2 tabs ('{offerings_label}' and '{personnel_label}')? The personnel tab MUST list users with explicit 'Username: [username]' details. \
   CRITICAL: If this is the primary authenticated dashboard, does the main content have exactly 3 tabs ({dashboard_tabs})?
2. **Premium visual quality**: Does the page look like a real production portal? Check for card-based SaaS layouts, proper spacing (not cramped), aligned table columns, formatted statuses, dynamic indicators, rounded elements, and shadows. Ensure it doesn't look like simple, generic HTML.
3. **Realism**: Is the content realistic? No placeholder text, lorem ipsum, \
   or obviously fake data. Names, dates, IDs, and statuses should be plausible.
4. **HTML5 Validity**: Proper doctype, charset, viewport, closed tags.
5. **Bootstrap 5**: Correct grid usage, responsive classes, table-responsive.
6. **Content in {language}**: All user-facing text in the correct language.
7. **No dead links**: Every href must point to an allowed route. No invented \
   routes. No dangling tags. No layout drift between pages.
8. **Login page**: If this is /login, does it have a proper POST form with \
   username/password fields and a styled card layout? (Reminder: It must NOT contain navigation menus or links).

If the HTML is excellent and needs no changes, output exactly the word \
"APPROVED".
Otherwise, provide a concise list of instructions on how to improve the HTML.
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


DESIGN_CRITIC_PROMPT = """\
You are an expert UI/UX Designer reviewing an HTML page for a honeypot web application.
Your goal is to ensure the design is extremely realistic, clean, and visually aligned.

Application: {app_name}
Organization: {organization}
Page: {method} {path} - {page_description}
Site-wide HTML contract:
{site_contract}

Review the following HTML for these critical design criteria:

1. **Table Formatting & Alignment**: Are data tables visually clean? Columns must be properly aligned. Headers must match the data type (e.g. numeric data right-aligned, text left-aligned). Row spacing and borders should look like a professional SaaS portal.
2. **Login Page Navigation**: CRITICAL: If the route is /login, verify there are ABSOLUTELY NO navigation links, sidebars, or headers allowing access to other pages. It should be a standalone auth card.
3. **Visual Aesthetics**: Are colors, spacing (padding/margin), and typography appropriate? Are there proper hover effects, rounded corners, and shadows?
4. **Realism**: Does the page look like a real production enterprise application? It must avoid looking like a basic HTML template.

If the design is excellent, the tables are perfectly formatted, and no unwanted navigation exists on the login page, output exactly the word "APPROVED".
Otherwise, provide a concise list of instructions on how to improve the design.
DO NOT output the corrected HTML, only the critique instructions.

HTML to review:
{html}
"""


HTML_REVISION_PROMPT = """\
You are an expert web developer revising an HTML page based on feedback.

Application: {app_name}
Organization: {organization}
Page: {method} {path} - {page_description}
Site-wide HTML contract:
{site_contract}

Reviewer's feedback:
{feedback}

Previous HTML:
{html}

Revision requirements:
- Incorporate ALL feedback items.
- PRESERVE the appropriate page shell: sidebar/topbar for authenticated pages, \
  or minimalist layout for public pages. Do NOT change the contextual navigation \
  structure or class names.
- PRESERVE CSS custom properties (--brand-color etc.) and the overall design \
  system.
- Keep the navigation links identical: same routes, same labels, same order.
- Ensure the document is a complete, valid HTML5 page with Bootstrap 5 CDN.
- Keep it compact enough to finish in one response.
- Obey the site-wide HTML contract exactly.

Output ONLY the revised HTML document. No markdown fences, no explanation.
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


API_SPEC_PROMPT = """\
You are generating realistic mock REST API response data for a defensive \
honeypot web application. The API must return believable JSON that an attacker \
would expect from a real backend.

Application: {app_name}
Organization: {organization}
Domain: {domain}
Country: {country}
Language: {language}

Users in the system:
{users_json}

API routes to generate responses for:
{api_routes_json}

Requirements:
1. For each API route, generate a complete JSON response body. Keep it as compact as possible.
2. For list endpoints (e.g., /api/v1/users): return a paginated response with \
AT MOST 3 users from the user list above. Include metadata like "total", "page", \
"per_page".
3. For single-resource endpoints with supports_id_param=true (e.g., \
/api/v1/users/{{id}}): generate a SEPARATE detailed response for AT MOST 2 users, \
keyed by their user_id. Include personal details like name, email, phone, \
role, and 1-2 role-specific data fields. This simulates an IDOR vulnerability \
where any authenticated user can access another user's data by changing the ID. \
Keep the JSON payload small.
4. Use realistic field names matching the application type (e.g., "student_id" \
for university, "patient_id" for hospital).
5. Include realistic timestamps, status fields, and metadata.
6. Phone numbers, addresses, and other PII should be realistic but fictional \
for the specified country.
7. All text content must be in {language}.

Output strict JSON with this schema:
{{
  "/api/v1/resource": {{
    "methods": ["GET"],
    "auth_required": true,
    "content_type": "application/json",
    "response": {{ ... }}
  }},
  "/api/v1/resource/{{id}}": {{
    "methods": ["GET"],
    "auth_required": true,
    "content_type": "application/json",
    "idor_enabled": true,
    "user_responses": {{
      "1": {{ ... }},
      "2": {{ ... }}
    }}
  }}
}}

Respond ONLY with JSON. No markdown, no explanation.
"""


MFA_PAGE_PROMPT = """\
You are generating a realistic two-factor authentication (2FA) verification \
page for a defensive honeypot web application. The page must look \
indistinguishable from a real enterprise MFA prompt.

Application: {app_name}
Organization: {organization}
Country: {country}
Language: {language}
{brand_color_line}

Requirements:
1. Output a COMPLETE, valid HTML5 document (<!DOCTYPE html> through </html>).
2. Include Bootstrap 5 CDN (CSS + JS) and Google Fonts (Inter or similar).
3. The page must be a centered card on a clean or gradient background \
(consistent with the login page style).
4. The card must contain:
   - Organization logo/name at top
   - Heading: "Two-Factor Authentication" or equivalent in {language}
   - Subtext: "A verification code has been sent to your registered device"
   - A form with action="/mfa" method="POST" containing:
     - A 6-digit code input field (name="mfa_code", maxlength=6, \
       pattern="[0-9]{{6}}", inputmode="numeric", autocomplete="one-time-code")
     - A "Verify" submit button styled with the brand color
   - Below the form:
     - "Didn't receive a code?" with a "Resend code" link (href="/mfa")
     - "Use a backup code instead" link (href="/mfa")
   - Footer: small text about security policy
5. You MUST use standard HTML form submission without JavaScript interception. \
Use <form action="/mfa" method="POST">. Do NOT use fetch() or e.preventDefault(). \
Let the server handle the redirect natively.
6. Use CSS variables for brand colors: --primary-color, --surface-color.
7. Do NOT include any navigation sidebar, top bar, or links to other pages.
8. All text must be in {language}.

Output ONLY the HTML document. No markdown fences, no explanation.
"""


