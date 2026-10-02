COMPOSE ?= docker compose
NODE_ID ?= node-local-1
ORCHESTRATOR_URL ?= http://localhost:8080
ANALYSIS_OUT ?= analysis/output
HONEYPOT_LOG ?= honeybot/honeypot.log

ifneq (,$(wildcard .env))
include .env
export
endif

.PHONY: env certs up down logs ps register-node up-node dashboard analyze db-analysis db-shell clean-analysis assets

env:
	@test -f .env || cp .env.example .env
	@echo "Using .env (edit secrets before public deployment)."

certs:
	@ORCHESTRATOR_CN=$${ORCHESTRATOR_CN:-localhost} bash scripts/gen_pki.sh $(NODE_ID)

up: env certs
	$(COMPOSE) up -d --build postgres orchestrator nginx dashboard

up-node: env certs
	$(COMPOSE) --profile node up -d --build honeybot

push-honeybot:
	@echo "Building and pushing honeybot for linux/amd64..."
	docker buildx build --platform linux/amd64 -t $${HONEYBOT_IMAGE:-heillmpot/honeybot:latest} --push ./honeybot

dashboard: env
	$(COMPOSE) up -d --build dashboard

down:
	$(COMPOSE) down

logs:
	$(COMPOSE) logs -f --tail=200

ps:
	$(COMPOSE) ps

register-node:
	python3 scripts/register_node.py \
		--url $(ORCHESTRATOR_URL) \
		--node-id $(NODE_ID) \
		--api-key "$${NODE_API_KEY:-dev-api-key}" \
		--env-file .env

analyze:
	python3 scripts/analyze_honeypot.py --log-file $(HONEYPOT_LOG) --out $(ANALYSIS_OUT)

db-analysis:
	$(COMPOSE) exec -T postgres psql -U $${DB_USER:-orchestrator_app} -d $${DB_NAME:-honeypot_db} < analysis/summary.sql

db-shell:
	$(COMPOSE) exec postgres psql -U $${DB_USER:-orchestrator_app} -d $${DB_NAME:-honeypot_db}

clean-analysis:
	rm -rf $(ANALYSIS_OUT)

assets:
	python3 scripts/render_demo_gif.py --output docs/assets/demo.gif
