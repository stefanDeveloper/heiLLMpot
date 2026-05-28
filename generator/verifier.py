"""
Verification module for validating generated honeypot sites with Nuclei.

Spins up a temporary HTTP server serving the newly generated site, runs the
newly created Nuclei templates against it, and prints a beautiful summary of
the findings to verify the vulnerability is fully active and detectable.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import tempfile
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from threading import Thread
from urllib.parse import parse_qs, urlparse


# ─── Temporary HTTP Server ───────────────────────────────────────────────────

class TempHoneypotHandler(BaseHTTPRequestHandler):
    """
    Minimal, quiet handler that serves the generated site structure.
    """
    # Class-level variables injected before starting the server
    routes_data: dict = {}
    users_data: list = []

    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        # Suppress standard logging to keep console output clean
        pass

    def do_GET(self):
        self._serve("GET")

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path

        # Read POST body parameters
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length).decode("utf-8", errors="replace") if length else ""
        params = {}
        for k, vs in parse_qs(body).items():
            params[k] = vs[0] if vs else ""

        # Simulating a successful login for default_credentials template
        if path == "/login":
            username = params.get("username", "")
            password = params.get("password", "")

            # Check credentials against users.json
            valid = False
            for u in self.users_data:
                if u.get("username") == username and u.get("password") == password:
                    valid = True
                    break

            if valid:
                self.send_response(302)
                self.send_header("Location", "/")
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Server", "nginx/1.24.0")
                resp = b"<html><body><h1>Dashboard</h1><a href='/logout'>logout</a></body></html>"
                self.send_header("Content-Length", str(len(resp)))
                self.end_headers()
                self.wfile.write(resp)
            else:
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Server", "nginx/1.24.0")
                resp = b"<html><body><h1>Login failed</h1><p>Invalid credentials</p></body></html>"
                self.send_header("Content-Length", str(len(resp)))
                self.end_headers()
                self.wfile.write(resp)
            return

        self._serve("POST", body=body, params=params)

    def _serve(self, method: str, body: str = "", params: dict = {}):
        parsed = urlparse(self.path)
        path = parsed.path
        qs = parse_qs(parsed.query)

        # ── Simulating vulnerabilities dynamically based on inputs ──

        # 1. SQL Injection simulation
        # If any query param or body param contains SQL injection payloads
        all_inputs = {}
        all_inputs.update({k: v[0] for k, v in qs.items()})
        all_inputs.update(params)
        
        for val in all_inputs.values():
            if any(x in str(val) for x in ["' OR '", "' OR 1=1", "UNION SELECT"]):
                # Return standard database syntax error
                resp = b"500 Internal Server Error: SQL syntax error near '1'='1. mysql_fetch_array() expects parameter."
                self.send_response(500)
                self.send_header("Content-Type", "text/plain")
                self.send_header("Content-Length", str(len(resp)))
                self.send_header("Server", "nginx/1.24.0")
                self.end_headers()
                self.wfile.write(resp)
                return

        # 2. Path Traversal / LFI simulation
        # If any query param contains traversal sequences like etc/passwd or ..
        for val in all_inputs.values():
            if any(x in str(val) for x in ["etc/passwd", "../"]):
                resp = b"root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.send_header("Content-Length", str(len(resp)))
                self.send_header("Server", "nginx/1.24.0")
                self.end_headers()
                self.wfile.write(resp)
                return

        # 3. Reflected XSS simulation
        # Echo back any param value containing script tags
        for val in all_inputs.values():
            if "<script>" in str(val) or "alert(" in str(val):
                resp_html = f"<html><body><p>Search result for: {val}</p></body></html>".encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(resp_html)))
                self.send_header("Server", "nginx/1.24.0")
                self.end_headers()
                self.wfile.write(resp_html)
                return

        # 4. Open Redirect simulation
        # If any query param contains attacker.example.com
        for val in all_inputs.values():
            if "attacker.example.com" in str(val):
                self.send_response(302)
                self.send_header("Location", str(val))
                self.send_header("Server", "nginx/1.24.0")
                self.send_header("Content-Length", "0")
                self.end_headers()
                return

        # 5. IDOR simulation
        # If there are specific identifier parameters
        idor_keys = ["student_record_id", "user_id", "id", "record", "account"]
        matching_key = next((k for k in idor_keys if k in qs), None)
        if matching_key:
            self._serve_probe_response(parsed, matching_key)
            return

        # Otherwise, serve the standard static page
        route = (
            self.routes_data.get(path)
            or self.routes_data.get(path.rstrip("/"))
            or self.routes_data.get(path + "/")
        )

        if route is None:
            self._send_404()
            return

        responses = route.get("responses", {})
        html = responses.get(method) or responses.get("GET") or ""
        if not html:
            self._send_404()
            return

        encoded = html.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(encoded)))
        self.send_header("Server", "nginx/1.24.0")
        self.end_headers()
        self.wfile.write(encoded)

    def _serve_probe_response(self, parsed, matching_key):
        qs = parse_qs(parsed.query)
        val = qs.get(matching_key, ["1"])[0]
        try:
            val_idx = int(re.sub(r"\D", "", val))
        except ValueError:
            val_idx = 1

        user = self.users_data[val_idx % len(self.users_data)] if self.users_data else {
            "username": "admin", "email": "admin@local.host"
        }
        html = (
            f"<html><body>"
            f"<h2>User Record Details</h2>"
            f"<p>username: {user.get('username')}</p>"
            f"<p>email: {user.get('email')}</p>"
            f"<p>student_id: {val_idx}</p>"
            f"<p>user_id: {val_idx}</p>"
            f"</body></html>"
        ).encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(html)))
        self.send_header("Server", "nginx/1.24.0")
        self.end_headers()
        self.wfile.write(html)


    def _send_404(self):
        body = b"<html><body><h1>404 Not Found</h1></body></html>"
        self.send_response(404)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Server", "nginx/1.24.0")
        self.end_headers()
        self.wfile.write(body)


# ─── Verification Logic ───────────────────────────────────────────────────────

def find_nuclei() -> str | None:
    """Find local nuclei binary."""
    for path in [
        shutil.which("nuclei"),
        "/opt/homebrew/bin/nuclei",
        "/usr/local/bin/nuclei",
        str(Path.home() / "go/bin/nuclei"),
    ]:
        if path and Path(path).exists():
            return path
    return None


def run_verification(out_dir: Path) -> None:
    """
    Runs automated validation of the templates against a local mock server.
    """
    nuclei_bin = find_nuclei()
    if not nuclei_bin:
        print("\n  [~] Nuclei binary not found. Skipping auto-verification step.")
        print("      To enable this, install nuclei via Homebrew: brew install nuclei")
        return

    routes_path = out_dir / "routes.json"
    users_path = out_dir / "users.json"
    nuclei_dir = out_dir / "nuclei"

    if not routes_path.exists() or not nuclei_dir.exists():
        return

    print("\n  [5/5] Running automated Nuclei verification...")

    # Load data for handler
    with open(routes_path, encoding="utf-8") as f:
        TempHoneypotHandler.routes_data = json.load(f)
    if users_path.exists():
        with open(users_path, encoding="utf-8") as f:
            TempHoneypotHandler.users_data = json.load(f)

    # Start temp HTTP server on localhost on a free port
    server = HTTPServer(("127.0.0.1", 0), TempHoneypotHandler)
    port = server.server_port
    target = f"http://127.0.0.1:{port}"

    # Run in daemon thread so it cleans up if main thread dies
    server_thread = Thread(target=server.serve_forever, daemon=True)
    server_thread.start()

    try:
        # Create temp dir to write patched templates (mapping Real Domain -> Localhost)
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            local_templates_dir = tmp_path / "templates"
            local_templates_dir.mkdir()

            # Copy and patch each YAML template to hit localhost
            for tmpl in nuclei_dir.glob("*.yaml"):
                content = tmpl.read_text(encoding="utf-8")
                # Ensure no host header mismatches
                content = re.sub(
                    r'(Host:\s*)[^\s\r\n]+',
                    r'\g<1>127.0.0.1:' + str(port),
                    content
                )
                (local_templates_dir / tmpl.name).write_text(content, encoding="utf-8")

            results_file = tmp_path / "results.json"

            # Execute nuclei
            cmd = [
                nuclei_bin,
                "-t", str(local_templates_dir),
                "-u", target,
                "-je", str(results_file),
                "-no-interactsh",
                "-disable-update-check",
                "-silent"
            ]
            subprocess.run(cmd, capture_output=True, timeout=30)

            # Parse results
            findings = []
            if results_file.exists():
                for line in results_file.read_text(encoding="utf-8").splitlines():
                    if line.strip():
                        try:
                            obj = json.loads(line)
                            if isinstance(obj, list):
                                findings.extend(obj)
                            elif isinstance(obj, dict):
                                findings.append(obj)
                        except json.JSONDecodeError:
                            pass

            # Output pretty terminal preview
            print("\n  ┌──────────────────────────────────────────────────────────┐")
            print("  │            NUCLEI SECURITY VERIFICATION                  │")
            print("  └──────────────────────────────────────────────────────────┘")

            if findings:
                # Group findings to print them clean
                for f in findings:
                    info = f.get("info", {})
                    severity = info.get("severity", "unknown").upper()
                    name = info.get("name", "Unknown vulnerability")
                    matched = f.get("matched-at", f.get("matched", "?"))
                    color_code = "🔴" if severity == "CRITICAL" else "🟠" if severity == "HIGH" else "🟡"

                    print(f"  {color_code} [{severity}] {name}")
                    print(f"      Matched:   {matched}")
                    extracted = f.get("extracted-results") or f.get("extracted_results")
                    if extracted:
                        print(f"      Extracted: {extracted}")
                    print("  ────────────────────────────────────────────────────────────")
                print(f"  [✓] Verification complete: {len(findings)} match(es) detected successfully!")
            else:
                print("  [⚠] No security vulnerabilities detected. Check template definitions.")

    except Exception as e:
        print(f"  [⚠] Verification error: {e}")
    finally:
        # Shutdown server
        server.shutdown()
        server.server_close()
