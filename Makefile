.PHONY: up down seed rules alerts test logs clean help

PYTHON ?= python3
VENV := .venv
PIP := $(VENV)/bin/pip
PY := $(VENV)/bin/python

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*## ' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*## "}; {printf "  \033[36m%-10s\033[0m %s\n", $$1, $$2}'

$(VENV)/bin/activate: requirements.txt
	$(PYTHON) -m venv $(VENV)
	$(PIP) install -q -r requirements.txt
	@touch $(VENV)/bin/activate

up: ## Start the Elastic stack (ES + Kibana + Filebeat)
	docker compose up -d
	@echo "Waiting for Kibana at http://localhost:5601 (elastic/changeme)..."
	@until curl -s http://localhost:5601/api/status | grep -q '"level":"available"'; do sleep 5; printf .; done
	@echo "\nStack is up."

down: ## Stop the stack (keeps data volume)
	docker compose down

seed: $(VENV)/bin/activate ## Generate sample logs, index them, and import the detection rules
	$(PY) scripts/generate_logs.py
	$(PY) scripts/seed.py
	$(PY) scripts/load_rules.py
	@echo "Seeded. Alerts appear within ~1 minute: run 'make alerts'."

alerts: $(VENV)/bin/activate ## Print the triage table of triggered alerts
	$(PY) -m alert_consumer

test: $(VENV)/bin/activate ## Run the pytest suite
	$(PY) -m pytest tests/ -v

logs: ## Tail stack logs
	docker compose logs -f

clean: down ## Stop the stack AND delete all indexed data
	docker compose down -v
	rm -rf $(VENV)
