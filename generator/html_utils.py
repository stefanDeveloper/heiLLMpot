"""
HTML post-processing and validation utilities.
"""

from __future__ import annotations

import json
import re


# ─── Think-tag / JSON helpers ─────────────────────────────────────────────────

def remove_think_tags(text: str) -> str:
    """Remove <think>...</think> blocks produced by reasoning models."""
    return re.sub(r"<think>.*?</think>", "", text, flags=re.DOTALL).strip()


def extract_json(text: str) -> dict:
    """Extract JSON from LLM output, handling markdown fences."""
    text = remove_think_tags(text)

    # Try to find JSON in a markdown code fence
    match = re.search(r"```(?:json)?\s*(.*?)```", text, re.DOTALL)
    if match:
        text = match.group(1).strip()

    # Try to find the outermost { ... }
    start = text.find("{")
    end = text.rfind("}")
    if start != -1 and end != -1 and end > start:
        text = text[start : end + 1]

    return json.loads(text)


# ─── HTML post-processing ─────────────────────────────────────────────────────

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
    html = re.sub(
        r"<j\s+Doctype\s+html>", "<!DOCTYPE html>", html, flags=re.IGNORECASE
    )

    # Remove HTTP headers that leaked into the HTML body
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
    """Basic HTML validation — check for common structural issues."""
    issues: list[str] = []

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


def verify_vulnerability_static(
    html: str, vuln_type: str, parameter: str
) -> tuple[bool, str]:
    """Perform basic static analysis to find common security anti-patterns or indicators."""
    html_lower = html.lower()

    if "sql" in vuln_type.lower():
        # Look for typical form fields matching the parameter
        if f'name="{parameter}"' not in html and f"name='{parameter}'" not in html:
            return False, f"Vulnerable parameter '{parameter}' not found in any form field."

    if "xss" in vuln_type.lower():
        # Check if the parameter is at least mentioned or if there are sinks
        if f'name="{parameter}"' not in html and f"name='{parameter}'" not in html:
            return False, f"Parameter '{parameter}' not found in form for XSS injection."

    return True, "Static check passed."
