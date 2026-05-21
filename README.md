# heiLLMpot

LLM-assisted honeypot framework for generating context-aware fake web portals, serving them through a C++ honeybot, and collecting events in a central orchestrator for analysis.

## Components

- `generator/`: Ollama-based fake portal generator. Outputs JSON site definitions consumed by the honeybot.
- `honeybot/`: C++ HTTP honeypot runtime with structured JSONL logging and async orchestrator forwarding. SSH is scaffolded but currently disabled by default.
- `orchestrator/`: C++ Oat++ API with PostgreSQL storage, JWT node auth, stats endpoints, and bot/human classification worker.
- `nginx/`: TLS and mTLS reverse proxy for production-style orchestrator exposure.
- `analysis/` and `scripts/analyze_honeypot.py`: local log summaries and database query examples.

## Quick Start

1. Create local config and secrets:

```bash
cp .env.example .env
openssl rand -hex 32
```

Put the generated value into `JWT_SECRET` in `.env`, and change `DB_PASSWORD`.

2. Generate local PKI and start the central stack:

```bash
make up NODE_ID=node-local-1
docker compose ps
curl http://localhost:8080/health
```

The orchestrator API is bound to `127.0.0.1:8080` for local administration. Nginx exposes HTTPS/mTLS on port `443`.

3. Generate one or more fake sites:

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install requests tqdm
python generator/generate_multi_route.py \
  --models llama3.2:3b \
  --count 1 \
  --context university \
  --country US \
  --language English
```

Generated site JSON files go into `generated_sites/`.

4. Register a honeypot node:

```bash
make register-node NODE_ID=node-local-1 NODE_API_KEY='replace-me'
```

This writes the returned `JWT_TOKEN` and `NODE_ID` into `.env` for the Dockerized `honeybot` profile.

5. Start the optional local honeybot node:

```bash
docker compose --profile node up -d --build honeybot
```

HTTP is available on `http://localhost:8081`; HTTPS is available on `https://localhost:8443`.

## Analysis

Summarize local JSONL logs:

```bash
make analyze HONEYPOT_LOG=honeybot/honeypot.log
```

Outputs are written to `analysis/output/`:

- `summary.md`: human-readable overview
- `summary.json`: machine-readable aggregate metrics
- `events.csv`: normalized event rows
- `sessions.csv`: session-level rollup

Run database analysis queries against the orchestrator:

```bash
make db-analysis
```

The SQL lives in `analysis/summary.sql` and covers top IPs, requested paths, credentials, user agents, daily stats, and command events.

## Useful Commands

```bash
make up              # build and start postgres, orchestrator, nginx
make up-node         # build and start the optional honeybot profile
make logs            # follow Docker Compose logs
make db-shell        # open psql inside the Postgres container
make down            # stop the stack
```

## Configuration

The orchestrator reads `orchestrator/config/orchestrator.json`, then applies environment overrides such as `DB_HOST`, `DB_PASSWORD`, `JWT_SECRET`, `PORT`, and `WORKER_INTERVAL_SEC`.

The honeybot reads `honeybot/config/honeypot.json`, then applies environment overrides such as `HTTP_PORT`, `HTTPS_PORT`, `SITES_DIR`, `ORCHESTRATOR_URL`, `NODE_ID`, and `JWT_TOKEN`.

Keep generated certificates, `.env`, logs, build trees, and generated sites out of git. The repo `.gitignore` and Docker ignore files are set up for that.

## Safety

Run honeypots only in isolated research environments where you are authorized to collect attack traffic. Treat captured credentials, IP addresses, and commands as sensitive operational data.
