#!/usr/bin/env python3
"""Register a honeypot node and optionally write a node config file."""

from __future__ import annotations

import argparse
import json
import ssl
import sys
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


def build_ssl_context(args: argparse.Namespace) -> ssl.SSLContext | None:
    if not args.url.startswith("https://"):
        return None

    if args.insecure:
        context = ssl._create_unverified_context()
    elif args.ca_cert:
        context = ssl.create_default_context(cafile=args.ca_cert)
    else:
        context = ssl.create_default_context()

    if args.client_cert and args.client_key:
        context.load_cert_chain(args.client_cert, args.client_key)
    return context


def post_json(url: str, payload: dict, context: ssl.SSLContext | None) -> dict:
    body = json.dumps(payload).encode("utf-8")
    request = Request(
        url,
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urlopen(request, timeout=20, context=context) as response:
            return json.loads(response.read().decode("utf-8"))
    except HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        raise SystemExit(f"Registration failed: HTTP {exc.code}: {detail}") from exc
    except URLError as exc:
        raise SystemExit(f"Registration failed: {exc.reason}") from exc


def update_config(path: Path, args: argparse.Namespace, token: str) -> None:
    if path.exists():
        config = json.loads(path.read_text(encoding="utf-8"))
    else:
        config = {}

    orchestrator = config.setdefault("orchestrator", {})
    orchestrator["enabled"] = True
    orchestrator["url"] = args.forward_url or args.url.rstrip("/")
    orchestrator["node_id"] = args.node_id
    orchestrator["jwt_token"] = token
    if args.client_cert:
        orchestrator["client_cert"] = args.client_cert
    if args.client_key:
        orchestrator["client_key"] = args.client_key
    if args.ca_cert:
        orchestrator["ca_cert"] = args.ca_cert

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(config, indent=2) + "\n", encoding="utf-8")


def update_env_file(path: Path, args: argparse.Namespace, token: str) -> None:
    updates = {
        "NODE_ID": args.node_id,
        "JWT_TOKEN": token,
    }
    existing = path.read_text(encoding="utf-8").splitlines() if path.exists() else []
    seen: set[str] = set()
    output: list[str] = []

    for line in existing:
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in line:
            output.append(line)
            continue
        key = line.split("=", 1)[0].strip()
        if key in updates:
            output.append(f"{key}={updates[key]}")
            seen.add(key)
        else:
            output.append(line)

    for key, value in updates.items():
        if key not in seen:
            output.append(f"{key}={value}")

    path.write_text("\n".join(output) + "\n", encoding="utf-8")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Register a honeybot node with the orchestrator."
    )
    parser.add_argument("--url", default="http://localhost:8080",
                        help="Orchestrator base URL for registration.")
    parser.add_argument("--forward-url",
                        help="URL the node should use when forwarding events.")
    parser.add_argument("--node-id", required=True)
    parser.add_argument("--region", default="local")
    parser.add_argument("--ip-address", default="")
    parser.add_argument("--api-key", required=True)
    parser.add_argument("--config", type=Path,
                        help="Optional honeybot config path to update.")
    parser.add_argument("--env-file", type=Path,
                        help="Optional .env file to update with NODE_ID and JWT_TOKEN.")
    parser.add_argument("--client-cert", help="Client certificate for HTTPS/mTLS.")
    parser.add_argument("--client-key", help="Client private key for HTTPS/mTLS.")
    parser.add_argument("--ca-cert", help="CA certificate for HTTPS verification.")
    parser.add_argument("--insecure", action="store_true",
                        help="Disable HTTPS certificate verification.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    endpoint = args.url.rstrip("/") + "/api/v1/nodes/register"
    payload = {
        "node_id": args.node_id,
        "region": args.region,
        "ip_address": args.ip_address,
        "api_key": args.api_key,
    }

    response = post_json(endpoint, payload, build_ssl_context(args))
    token = response.get("jwt_token")
    if not token:
        raise SystemExit(f"Registration response did not include jwt_token: {response}")

    print(f"Node registered: {args.node_id}")
    print(f"JWT token: {token}")

    if args.config:
        update_config(args.config, args, token)
        print(f"Updated config: {args.config}")
    if args.env_file:
        update_env_file(args.env_file, args, token)
        print(f"Updated env file: {args.env_file}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
