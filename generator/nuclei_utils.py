"""
Nuclei template generator for heiLLMpot honeypot sites.

All templates use {{BaseURL}} — Nuclei's built-in variable — so you can
point them at any host without editing:

    nuclei -t /path/to/site/nuclei/ -u http://127.0.0.1:8881

Supported vulnerability types (one template per site + always default_credentials):
  - SQL Injection (error-based)
  - Reflected XSS
  - Stored XSS
  - IDOR (Insecure Direct Object Reference)
  - Path Traversal / LFI
  - Open Redirect
  - Default/Weak Credentials (always generated regardless of vuln type)
"""

from __future__ import annotations

import textwrap
from pathlib import Path


# ─── Header builder ───────────────────────────────────────────────────────────

def _header(
    template_id: str,
    name: str,
    author: str,
    severity: str,
    description: str,
    tags: list[str],
) -> str:
    tags_str = ", ".join(tags)
    return textwrap.dedent(f"""\
        id: {template_id}

        info:
          name: {name}
          author: {author}
          severity: {severity}
          description: |
            {description}
          tags: {tags_str}
    """)


# ─── Individual template generators ──────────────────────────────────────────
# NOTE: All paths use {{{{BaseURL}}}} which Nuclei expands to the -u target.
# Double-braces {{ }} are Python's way of writing a literal { } inside an f-string.

def gen_sql_injection(domain: str, target_route: str, parameter: str, site_id: str) -> str:
    """Error-based SQL injection — fires when the server echoes a DB error."""
    path = target_route if target_route.startswith("/") else f"/{target_route}"
    header = _header(
        template_id=f"honeypot-sqli-{site_id[:8]}",
        name=f"SQL Injection – {domain}",
        author="heiLLMpot",
        severity="critical",
        description=(
            f"Detects error-based SQL injection via the '{parameter}' parameter "
            f"at {path} on {domain}. Intentional honeypot vulnerability."
        ),
        tags=["sqli", "injection", "honeypot"],
    )
    body = f"{parameter}=' OR '1'='1&password=test"
    return header + f"""
http:
  - method: POST
    path:
      - "{{{{BaseURL}}}}{path}"

    body: "{body}"

    matchers-condition: or
    matchers:
      - type: word
        words:
          - "SQL syntax"
          - "mysql_fetch"
          - "ORA-01756"
          - "syntax error"
          - "Unclosed quotation mark"
          - "quoted string not properly terminated"
        part: body
        case-insensitive: true

      - type: status
        status:
          - 500

    extractors:
      - type: regex
        regex:
          - '(?i)(sql|mysql|sqlite|postgresql|oracle)[^<]{{0,80}}'
        part: body
"""


def gen_reflected_xss(domain: str, target_route: str, parameter: str, site_id: str) -> str:
    """Reflected XSS — payload echoed back unescaped in the response body."""
    path = target_route if target_route.startswith("/") else f"/{target_route}"
    payload_raw = "<script>alert(1)</script>"
    payload_enc = "%3Cscript%3Ealert%281%29%3C%2Fscript%3E"
    header = _header(
        template_id=f"honeypot-rxss-{site_id[:8]}",
        name=f"Reflected XSS – {domain}",
        author="heiLLMpot",
        severity="high",
        description=(
            f"Detects reflected XSS via the '{parameter}' parameter "
            f"at {path} on {domain}. Intentional honeypot vulnerability."
        ),
        tags=["xss", "reflected", "honeypot"],
    )
    return header + f"""
http:
  - method: GET
    path:
      - "{{{{BaseURL}}}}{path}?{parameter}={payload_enc}"

    matchers-condition: and
    matchers:
      - type: word
        words:
          - "{payload_raw}"
        part: body

      - type: word
        words:
          - "text/html"
        part: header
"""


def gen_stored_xss(domain: str, target_route: str, parameter: str, site_id: str) -> str:
    """Stored XSS — submit a payload then verify it's reflected unescaped."""
    path = target_route if target_route.startswith("/") else f"/{target_route}"
    marker = f"heiLLMpot-xss-{site_id[:8]}"
    header = _header(
        template_id=f"honeypot-sxss-{site_id[:8]}",
        name=f"Stored XSS – {domain}",
        author="heiLLMpot",
        severity="high",
        description=(
            f"Detects stored XSS via the '{parameter}' field at {path} on {domain}. "
            "Submits a marker payload then checks if it's reflected back unescaped. "
            "Intentional honeypot vulnerability."
        ),
        tags=["xss", "stored", "honeypot"],
    )
    return header + f"""
http:
  - raw:
      - |
        POST {path} HTTP/1.1
        Host: {{{{Hostname}}}}
        Content-Type: application/x-www-form-urlencoded

        {parameter}=<script>console.log('{marker}')</script>

  - method: GET
    path:
      - "{{{{BaseURL}}}}{path}"

    matchers:
      - type: word
        words:
          - "{marker}"
        part: body
"""


def gen_idor(domain: str, target_route: str, parameter: str, site_id: str) -> str:
    """IDOR — probe sequential IDs and check if another user's data is returned."""
    path = target_route if target_route.startswith("/") else f"/{target_route}"
    header = _header(
        template_id=f"honeypot-idor-{site_id[:8]}",
        name=f"IDOR – {domain}",
        author="heiLLMpot",
        severity="high",
        description=(
            f"Detects IDOR via the '{parameter}' parameter at {path} on {domain}. "
            "Probes predictable integer IDs and checks for PII disclosure in response. "
            "Intentional honeypot vulnerability."
        ),
        tags=["idor", "access-control", "honeypot"],
    )
    return header + f"""
http:
  - method: GET
    path:
      - "{{{{BaseURL}}}}{path}?{parameter}=1"
      - "{{{{BaseURL}}}}{path}?{parameter}=2"
      - "{{{{BaseURL}}}}{path}?{parameter}=100"

    matchers-condition: and
    matchers:
      - type: status
        status:
          - 200

      - type: word
        words:
          - "email"
          - "username"
          - "student_id"
          - "user_id"
          - "profile"
        condition: or
        part: body
        case-insensitive: true

    extractors:
      - type: regex
        regex:
          - '(?i)(email|username|student_id|user_id)[^<]{{0,30}}'
        part: body
"""


def gen_path_traversal(domain: str, target_route: str, parameter: str, site_id: str) -> str:
    """Path traversal / LFI — probes for /etc/passwd disclosure via encoded paths."""
    path = target_route if target_route.startswith("/") else f"/{target_route}"
    header = _header(
        template_id=f"honeypot-lfi-{site_id[:8]}",
        name=f"Path Traversal / LFI – {domain}",
        author="heiLLMpot",
        severity="critical",
        description=(
            f"Detects path traversal (LFI) via the '{parameter}' parameter "
            f"at {path} on {domain}. Tests multiple encoding variants for /etc/passwd. "
            "Intentional honeypot vulnerability."
        ),
        tags=["lfi", "path-traversal", "honeypot"],
    )
    return header + f"""
http:
  - method: GET
    path:
      - "{{{{BaseURL}}}}{path}?{parameter}=../../../../etc/passwd"
      - "{{{{BaseURL}}}}{path}?{parameter}=..%2F..%2F..%2F..%2Fetc%2Fpasswd"
      - "{{{{BaseURL}}}}{path}?{parameter}=....//....//....//etc/passwd"
      - "{{{{BaseURL}}}}{path}?{parameter}=%252e%252e%252f%252e%252e%252fetc%252fpasswd"

    matchers-condition: and
    matchers:
      - type: regex
        regex:
          - "root:[x*]:0:0:"
        part: body

      - type: status
        status:
          - 200
"""


def gen_command_injection(domain: str, target_route: str, parameter: str, site_id: str) -> str:
    """Command injection — checks if the server executes an appended shell command."""
    path = target_route if target_route.startswith("/") else f"/{target_route}"
    payload = ";id"
    payload_enc = "%3Bid"
    header = _header(
        template_id=f"honeypot-rce-{site_id[:8]}",
        name=f"Command Injection (RCE) – {domain}",
        author="heiLLMpot",
        severity="critical",
        description=(
            f"Detects OS command injection via the '{parameter}' parameter at {path} on {domain}. "
            "Checks if the server blindly executes appended shell commands and reflects output. "
            "Intentional honeypot vulnerability."
        ),
        tags=["rce", "command-injection", "honeypot"],
    )
    return header + f"""
http:
  - method: GET
    path:
      - "{{{{BaseURL}}}}{path}?{parameter}=127.0.0.1{payload_enc}"
      - "{{{{BaseURL}}}}{path}?{parameter}=127.0.0.1{payload}"

    matchers-condition: and
    matchers:
      - type: regex
        regex:
          - "uid=[0-9]+\\(.*?\\) gid=[0-9]+\\(.*?\\)"
        part: body

      - type: status
        status:
          - 200
"""


def gen_open_redirect(domain: str, target_route: str, parameter: str, site_id: str) -> str:
    """Open redirect — checks if the server follows an arbitrary Location redirect."""
    path = target_route if target_route.startswith("/") else f"/{target_route}"
    redirect_target = "https://attacker.example.com"
    header = _header(
        template_id=f"honeypot-redirect-{site_id[:8]}",
        name=f"Open Redirect – {domain}",
        author="heiLLMpot",
        severity="medium",
        description=(
            f"Detects open redirect via the '{parameter}' parameter at {path} on {domain}. "
            "Checks if the server blindly redirects to an external URL. "
            "Intentional honeypot vulnerability."
        ),
        tags=["redirect", "open-redirect", "honeypot"],
    )
    return header + f"""
http:
  - method: GET
    path:
      - "{{{{BaseURL}}}}{path}?{parameter}={redirect_target}"
      - "{{{{BaseURL}}}}{path}?{parameter}=//attacker.example.com"

    matchers-condition: or
    matchers:
      - type: regex
        regex:
          - '(?i)location:\\s*https?://attacker\\.example\\.com'
        part: header

      - type: word
        words:
          - "attacker.example.com"
        part: header
"""


def gen_default_credentials(
    domain: str, target_route: str, site_id: str, users: list[dict]
) -> str:
    r"""Default/weak credentials — pitchfork-attacks login with all generated user accounts."""
    path = target_route if target_route.startswith("/") else f"/{target_route}"

    # Build credential pairs from actual generated users (max 5)
    cred_pairs: list[tuple[str, str]] = []
    for u in users[:5]:
        uname = u.get("username", "")
        pwd = u.get("password", "")
        if uname and pwd:
            cred_pairs.append((uname, pwd))
    if not cred_pairs:
        cred_pairs = [("admin", "admin"), ("admin", "password"), ("admin", "123456")]

    username_items = "\n".join(f'          - "{u}"' for u, _ in cred_pairs)
    password_items = "\n".join(f'          - "{p}"' for _, p in cred_pairs)

    header = _header(
        template_id=f"honeypot-defaultcreds-{site_id[:8]}",
        name=f"Default/Weak Credentials – {domain}",
        author="heiLLMpot",
        severity="critical",
        description=(
            f"Tests login at {path} on {domain} using the honeypot's intentionally "
            "weak credentials (all generated user accounts). "
            "Intentional honeypot vulnerability."
        ),
        tags=["default-login", "auth", "honeypot"],
    )
    return header + f"""
http:
  - raw:
      - |
        POST {path} HTTP/1.1
        Host: {{{{Hostname}}}}
        Content-Type: application/x-www-form-urlencoded

        username={{{{username}}}}&password={{{{password}}}}

    attack: pitchfork
    payloads:
      username:
{username_items}
      password:
{password_items}

    matchers-condition: and
    matchers:
      - type: status
        status:
          - 200
          - 302

      - type: word
        words:
          - "dashboard"
          - "logout"
          - "welcome"
          - "profile"
        condition: or
        part: body
        case-insensitive: true

      - type: word
        negative: true
        words:
          - "invalid"
          - "incorrect"
          - "failed"
          - "wrong"
        part: body
        case-insensitive: true
"""


# ─── README builder ───────────────────────────────────────────────────────────

def gen_readme(domain: str, vuln_type: str, templates: list[str]) -> str:
    """Generate a README.md explaining how to use the nuclei templates manually."""
    tmpl_list = "\n".join(f"- `{t}`" for t in templates)
    return f"""\
# Nuclei Templates — {domain}

Generated by **heiLLMpot**. These templates verify that the injected
vulnerability is detectable by an automated scanner.

## Vulnerability
**{vuln_type}**

## Templates
{tmpl_list}

## Manual Usage

### Prerequisite: a running honeypot
Start the test server (serves the generated site folder on localhost):
```bash
python3 test_honeypot_server.py --folder .. --port 8881
```

### Run all templates against localhost
```bash
nuclei -t . -u http://127.0.0.1:8881 -v
```

### Run a single template
```bash
nuclei -t default_credentials.yaml -u http://127.0.0.1:8881 -v
nuclei -t idor.yaml              -u http://127.0.0.1:8881 -v
```

### Run against the real deployed honeypot
```bash
nuclei -t . -u https://{domain} -v
```

### Validate templates (no network calls)
```bash
nuclei -t . -validate
```

> **Note:** All templates use `{{{{BaseURL}}}}` so `-u` controls the target —
> no manual editing needed.
"""


# ─── Vulnerability type classifier ───────────────────────────────────────────

_VULN_TYPE_MAP: dict[str, str] = {
    "sql injection": "sqli",
    "sqli": "sqli",
    "reflected xss": "rxss",
    "reflected cross-site scripting": "rxss",
    "stored xss": "sxss",
    "stored cross-site scripting": "sxss",
    "cross-site scripting": "rxss",
    "xss": "rxss",
    "idor": "idor",
    "insecure direct object reference": "idor",
    "path traversal": "lfi",
    "directory traversal": "lfi",
    "local file inclusion": "lfi",
    "lfi": "lfi",
    "open redirect": "redirect",
    "unvalidated redirect": "redirect",
    "command injection": "rce",
    "os command injection": "rce",
    "rce": "rce",
}


def _classify_vuln(vuln_type: str) -> str:
    """Map a free-text vulnerability type string to a canonical key."""
    lower = vuln_type.lower()
    for keyword, canonical in _VULN_TYPE_MAP.items():
        if keyword in lower:
            return canonical
    return "generic"


# ─── Public API ───────────────────────────────────────────────────────────────

def generate_nuclei_templates(
    output_dir: Path,
    site_id: str,
    domain: str,
    vulnerabilities: list[dict],
    users: list[dict],
) -> list[Path]:
    """
    Generate Nuclei YAML templates + README into *output_dir/nuclei/*.

    All templates use {{BaseURL}} — point at any host with:
        nuclei -t <nuclei_dir> -u http://127.0.0.1:8881

    Returns list of written file paths.
    """
    nuclei_dir = output_dir / "nuclei"
    nuclei_dir.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []

    # ── Vulnerability-specific templates ───────────────────────────────────────
    for vuln in vulnerabilities:
        vuln_type = vuln.get("type", "generic")
        target_route = vuln.get("target_route", "/")
        parameter = vuln.get("parameter", "input")
        canonical = _classify_vuln(vuln_type)
        vuln_path: Path | None = None

        if canonical == "sqli":
            vuln_path = nuclei_dir / f"sql_injection_{parameter}.yaml"
            vuln_path.write_text(
                gen_sql_injection(domain, target_route, parameter, site_id), encoding="utf-8"
            )
        elif canonical == "rxss":
            vuln_path = nuclei_dir / f"reflected_xss_{parameter}.yaml"
            vuln_path.write_text(
                gen_reflected_xss(domain, target_route, parameter, site_id), encoding="utf-8"
            )
        elif canonical == "sxss":
            vuln_path = nuclei_dir / f"stored_xss_{parameter}.yaml"
            vuln_path.write_text(
                gen_stored_xss(domain, target_route, parameter, site_id), encoding="utf-8"
            )
        elif canonical == "idor":
            vuln_path = nuclei_dir / f"idor_{parameter}.yaml"
            vuln_path.write_text(
                gen_idor(domain, target_route, parameter, site_id), encoding="utf-8"
            )
        elif canonical == "lfi":
            vuln_path = nuclei_dir / f"path_traversal_{parameter}.yaml"
            vuln_path.write_text(
                gen_path_traversal(domain, target_route, parameter, site_id), encoding="utf-8"
            )
        elif canonical == "rce":
            vuln_path = nuclei_dir / f"command_injection_{parameter}.yaml"
            vuln_path.write_text(
                gen_command_injection(domain, target_route, parameter, site_id), encoding="utf-8"
            )
        elif canonical == "redirect":
            vuln_path = nuclei_dir / f"open_redirect_{parameter}.yaml"
            vuln_path.write_text(
                gen_open_redirect(domain, target_route, parameter, site_id), encoding="utf-8"
            )
        else:
            # Fallback: reflected XSS catches unknown types
            vuln_path = nuclei_dir / f"generic_probe_{parameter}.yaml"
            vuln_path.write_text(
                gen_reflected_xss(domain, target_route, parameter, site_id), encoding="utf-8"
            )

        if vuln_path:
            written.append(vuln_path)

    # ── README ─────────────────────────────────────────────────────────────────
    readme = nuclei_dir / "README.md"
    
    vuln_types_str = ", ".join(v.get("type", "generic") for v in vulnerabilities)
    
    readme.write_text(
        gen_readme(domain, vuln_types_str, [p.name for p in written]),
        encoding="utf-8",
    )

    return written
