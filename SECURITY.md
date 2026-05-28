# Security Policy

heiLLMpot is defensive research software. It can collect traffic, credentials,
payloads, user agents, IP addresses, and other sensitive telemetry. Treat every
deployment as a security-sensitive system.

## Supported Versions

The public `main` branch is the supported research preview. Security fixes
should target `main` unless a maintained release branch exists.

## Reporting A Vulnerability

Please do not open a public issue for a vulnerability that could expose secrets,
weaken node authentication, bypass event integrity, or enable unsafe deployment.

Preferred reporting path:

1. Contact the maintainer privately.
2. Include a concise description, affected files, reproduction steps, and impact.
3. Avoid including real captured credentials or third-party traffic.

If no private contact is available for your fork, create a minimal public issue
that asks for a secure contact path without disclosing exploit details.

## Deployment Guidance

- Run nodes in isolated, authorized research networks.
- Bind the orchestrator admin/API port to localhost unless you have a hardened
  exposure plan.
- Rotate `JWT_SECRET`, node JWTs, database passwords, TLS keys, and client certs
  after testing.
- Do not reuse generated demo credentials anywhere else.
- Treat generated sites as untrusted content and review them before publishing.
- Keep logs and analysis outputs out of public commits.

## Data Handling

Captured data can be sensitive even when visitors interact with fake services.
Before sharing logs, screenshots, generated reports, or database dumps, remove:

- IP addresses and geolocation data
- User agents that may identify a person or organization
- Submitted credentials or tokens
- Request bodies, commands, paths, and headers that include sensitive values
- Timestamps if they can identify a live incident
