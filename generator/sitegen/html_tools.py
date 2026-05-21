"""Parsing and HTML cleanup helpers for generated site content."""

from __future__ import annotations

import json
import re
from html import unescape
from html.parser import HTMLParser
from urllib.parse import urlsplit, urlunsplit


VOID_TAGS = {
    "area", "base", "br", "col", "embed", "hr", "img", "input", "link",
    "meta", "param", "source", "track", "wbr",
}

STRUCTURAL_TAGS = {
    "article", "aside", "body", "div", "footer", "form", "header", "html",
    "li", "main", "nav", "section", "table", "tbody", "td", "tfoot", "th",
    "thead", "tr", "ul",
}

SAFE_EXTERNAL_ASSET_HOSTS = {
    "cdn.jsdelivr.net",
    "fonts.googleapis.com",
    "fonts.gstatic.com",
    "unpkg.com",
}

LAYOUT_GUARD_CSS = """\
:root { --sitegen-sidebar-width: 260px; }
html, body { max-width: 100%; overflow-x: hidden; }
body { min-width: 0; }
img, svg, canvas, video { max-width: 100%; height: auto; }
table { width: 100%; }
.container, .container-fluid, main, .main-content, .card, .table-responsive,
.list-group-item, .row, [class*="col-"] { min-width: 0; }
.table-responsive { overflow-x: auto; }
.text-truncate, .font-mono, code, pre { overflow-wrap: anywhere; }
.top-bar { gap: .75rem; }
@media (max-width: 991.98px) {
  .sidebar {
    position: static !important;
    width: 100% !important;
    min-height: auto !important;
    height: auto !important;
  }
  .main-content {
    margin-left: 0 !important;
    padding: 1rem !important;
  }
  .top-bar {
    position: sticky;
    top: 0;
    flex-wrap: wrap;
    align-items: flex-start !important;
  }
}
"""


class TagBalanceParser(HTMLParser):
    """Small HTML balance checker for catching truncated model output."""

    def __init__(self) -> None:
        super().__init__()
        self.stack: list[str] = []
        self.issues: list[str] = []

    def handle_starttag(self, tag: str, _attrs) -> None:
        tag = tag.lower()
        if tag not in VOID_TAGS:
            self.stack.append(tag)

    def handle_startendtag(self, tag: str, _attrs) -> None:
        tag = tag.lower()
        if tag not in VOID_TAGS:
            self.stack.append(tag)
            self.stack.pop()

    def handle_endtag(self, tag: str) -> None:
        tag = tag.lower()
        if tag in VOID_TAGS:
            return

        for index in range(len(self.stack) - 1, -1, -1):
            if self.stack[index] == tag:
                unclosed = [
                    item for item in self.stack[index + 1:]
                    if item in STRUCTURAL_TAGS
                ]
                if unclosed:
                    self.issues.append(
                        f"Unclosed tags before </{tag}>: "
                        f"{', '.join(unclosed[-5:])}"
                    )
                del self.stack[index:]
                return

        self.issues.append(f"Unexpected closing </{tag}>")

    def final_issues(self) -> list[str]:
        remaining = [tag for tag in self.stack if tag in STRUCTURAL_TAGS]
        if remaining:
            return self.issues + [
                f"Unclosed tags at end of document: "
                f"{', '.join(remaining[-5:])}"
            ]
        return self.issues


def remove_think_tags(text: str) -> str:
    """Remove <think>...</think> blocks from reasoning models."""
    return re.sub(r"<think>.*?</think>", "", text, flags=re.DOTALL).strip()


def extract_json(text: str) -> dict:
    """Extract JSON from LLM output, including common markdown wrappers."""
    text = remove_think_tags(text)

    match = re.search(r"```(?:json)?\s*(.*?)```", text, re.DOTALL)
    if match:
        text = match.group(1).strip()

    start = text.find("{")
    end = text.rfind("}")
    if start != -1 and end != -1 and end > start:
        text = text[start:end + 1]

    return json.loads(text)


def clean_html(html: str) -> str:
    """Post-process HTML output from LLMs to fix common issues."""
    html = re.sub(r"```(?:html)?\s*\n?", "", html).strip()
    html = remove_think_tags(html)

    html = re.sub(r"\{\{\s*[\w.]+\s*\}\}", "", html)
    html = re.sub(r"\{%.*?%\}", "", html, flags=re.DOTALL)
    html = re.sub(r"<(title|div|span|p|h[1-6])\.", r"<\1>", html)
    html = re.sub(
        r"<j\s+Doctype\s+html>",
        "<!DOCTYPE html>",
        html,
        flags=re.IGNORECASE,
    )

    if html.startswith("HTTP/"):
        parts = html.split("\n\n", 1)
        if len(parts) == 2:
            html = parts[1]

    html = re.sub(r"http://localhost:\d+", "", html)
    html = re.sub(r"http://127\.0\.0\.1:\d+", "", html)

    if not html.strip().lower().startswith("<!doctype"):
        if "<html" in html.lower():
            html = "<!DOCTYPE html>\n" + html
        else:
            html = (
                "<!DOCTYPE html>\n<html><head><title>Page</title></head>"
                f"<body>\n{html}\n</body></html>"
            )

    for tag in ["</html>", "</body>"]:
        if tag not in html.lower():
            if tag == "</html>":
                html += "\n</html>"
            elif tag == "</body>":
                html = html.replace("</html>", "</body>\n</html>")

    return html


def enforce_html_contract(html: str, allowed_routes: list[str],
                          current_path: str) -> tuple[str, list[str]]:
    """Apply deterministic safety/stability fixes to generated HTML."""
    html = clean_html(html)
    repairs: list[str] = []

    html, rewritten = normalize_interactive_targets(
        html,
        allowed_routes=allowed_routes,
        current_path=current_path,
    )
    if rewritten:
        repairs.append(f"rewrote {rewritten} non-route link/action target(s)")

    html, injected = inject_layout_guard(html)
    if injected:
        repairs.append("injected responsive layout guard CSS")

    return html, repairs


def normalize_interactive_targets(html: str, allowed_routes: list[str],
                                  current_path: str) -> tuple[str, int]:
    """Rewrite anchors/forms/buttons so generated pages do not invent routes."""
    allowed = normalize_allowed_routes(allowed_routes)
    current_path = current_path if current_path in allowed else "/"
    rewritten = 0

    def rewrite_tag(match: re.Match) -> str:
        nonlocal rewritten
        tag = match.group(0)
        tag_name = match.group(1).lower()
        attrs = {
            "a": "href",
            "form": "action",
            "button": "formaction",
        }.get(tag_name)
        if not attrs:
            return tag

        attr_re = re.compile(
            rf"\b({attrs})\s*=\s*(['\"])(.*?)\2",
            flags=re.IGNORECASE | re.DOTALL,
        )

        def rewrite_attr(attr_match: re.Match) -> str:
            nonlocal rewritten
            attr, quote, value = attr_match.groups()
            replacement = normalize_target(value, allowed, current_path)
            if replacement != value:
                rewritten += 1
            return f"{attr}={quote}{replacement}{quote}"

        return attr_re.sub(rewrite_attr, tag)

    updated = re.sub(
        r"<\s*(a|form|button)\b[^>]*>",
        rewrite_tag,
        html,
        flags=re.IGNORECASE | re.DOTALL,
    )
    return updated, rewritten


def normalize_allowed_routes(routes: list[str]) -> set[str]:
    normalized = {normalize_path(route) for route in routes if route}
    normalized.add("/")
    return normalized


def normalize_target(value: str, allowed_routes: set[str],
                     current_path: str) -> str:
    raw = unescape(value).strip()
    if not raw or raw == "#":
        return current_path
    if raw.startswith("#"):
        return f"{current_path}{raw}"
    if raw.startswith("?"):
        return f"{current_path}{raw}"

    lower = raw.lower()
    if lower.startswith(("javascript:", "mailto:", "tel:", "ftp:", "data:")):
        return current_path

    if lower.startswith(("http://", "https://")):
        parts = urlsplit(raw)
        if parts.netloc in SAFE_EXTERNAL_ASSET_HOSTS:
            return value
        path = normalize_path(parts.path or "/")
        if path in allowed_routes:
            return urlunsplit(("", "", path, parts.query, parts.fragment))
        return fallback_route(path, allowed_routes, current_path)

    if raw.startswith(("/", "./", "../")) or not re.match(r"^[a-z][a-z0-9+.-]*:", lower):
        parts = urlsplit(raw)
        path = normalize_path(parts.path)
        if path in allowed_routes:
            return urlunsplit(("", "", path, parts.query, parts.fragment))
        return fallback_route(path, allowed_routes, current_path)

    return current_path


def normalize_path(path: str) -> str:
    path = "/" + path.lstrip("./")
    path = re.sub(r"/+", "/", path)
    if len(path) > 1:
        path = path.rstrip("/")
    return path or "/"


def fallback_route(path: str, allowed_routes: set[str], current_path: str) -> str:
    lower_path = path.lower()
    if lower_path in {"/logout", "/log-out", "/signout", "/sign-out"}:
        return "/login" if "/login" in allowed_routes else "/"
    if lower_path in {"/dashboard", "/home"}:
        return "/" if "/" in allowed_routes else current_path

    for route in sorted(allowed_routes, key=len, reverse=True):
        if route != "/" and lower_path.startswith(route.lower() + "/"):
            return route

    return current_path if current_path in allowed_routes else "/"


def inject_layout_guard(html: str) -> tuple[str, bool]:
    if "sitegen-layout-guard" in html:
        return html, False

    style = f"\n<style id=\"sitegen-layout-guard\">\n{LAYOUT_GUARD_CSS}</style>\n"
    if re.search(r"</head\s*>", html, flags=re.IGNORECASE):
        return re.sub(
            r"</head\s*>",
            style + "</head>",
            html,
            count=1,
            flags=re.IGNORECASE,
        ), True

    if re.search(r"<body\b", html, flags=re.IGNORECASE):
        return re.sub(
            r"<body\b",
            style + "<body",
            html,
            count=1,
            flags=re.IGNORECASE,
        ), True

    return style + html, True


def validate_html_basic(html: str) -> tuple[bool, list[str]]:
    """Basic HTML validation for common LLM generation mistakes."""
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
    if re.search(r"</\s*(?:<|\n|$)", html):
        issues.append("Contains dangling closing tag")
    if re.search(r"<[a-zA-Z][^>]{0,240}$", html.strip()):
        issues.append("Looks truncated inside an HTML tag")

    parser = TagBalanceParser()
    try:
        parser.feed(html)
        parser.close()
        issues.extend(parser.final_issues()[:4])
    except Exception as e:
        issues.append(f"HTML parser error: {e}")

    return len(issues) == 0, issues


def json_for_prompt(value) -> str:
    """Serialize JSON-ish values for prompt context."""
    return json.dumps(value, indent=2, ensure_ascii=False)
