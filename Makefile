.DEFAULT_GOAL := help
SHELL := /bin/bash

UV       ?= uv
ENV_FILE ?= .env.local
# Only pass --env-file when the file exists (keeps CI happy without one).
ENV_ARG  := $(if $(wildcard $(ENV_FILE)),--env-file $(ENV_FILE),)
UV_RUN   := $(UV) run $(ENV_ARG)
PYTHON   := $(UV_RUN) python
MANAGE   := $(PYTHON) manage.py
PORT     ?= 8000

.PHONY: help install sync lock upgrade run migrate makemigrations shell \
        superuser collectstatic test lint format fix check ci clean \
        build up ps down stop rm logs d-migrate d-collectstatic d-superuser d-shell

help: ## Show this help
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

# --- environment -------------------------------------------------------------

install: ## Install runtime + dev dependencies into .venv
	$(UV) sync

sync: install ## Alias for install

lock: ## Regenerate uv.lock
	$(UV) lock

upgrade: ## Upgrade all dependencies to latest compatible versions
	$(UV) lock --upgrade
	$(UV) sync

# --- django ------------------------------------------------------------------

run: ## Run the Django development server (PORT=8000)
	$(MANAGE) runserver 0.0.0.0:$(PORT)

migrate: ## Apply database migrations
	$(MANAGE) migrate

makemigrations: ## Create new migrations based on model changes
	$(MANAGE) makemigrations

shell: ## Open a Django shell
	$(MANAGE) shell

superuser: ## Create a Django superuser
	$(MANAGE) createsuperuser

collectstatic: ## Collect static files
	$(MANAGE) collectstatic --noinput

# --- quality gates -----------------------------------------------------------

test: ## Run the Django test suite
	$(MANAGE) test

lint: ## Check code with ruff (no changes)
	$(UV_RUN) ruff check .
	$(UV_RUN) ruff format --check .

format: ## Auto-format code with ruff
	$(UV_RUN) ruff format .

fix: ## Auto-fix lint issues and format
	$(UV_RUN) ruff check --fix .
	$(UV_RUN) ruff format .

check: lint test ## Run lint + tests (local pre-commit gate)

ci: check ## CI entry point (same as check)

# --- docker compose ----------------------------------------------------------

build: ## Build the docker image
	docker compose build

up: ## Start the stack in the background
	docker compose up -d

ps: ## Show running compose services
	docker compose ps

logs: ## Tail compose logs
	docker compose logs -f

stop: ## Stop compose services
	docker compose stop

rm: stop ## Remove stopped compose containers
	docker compose rm -f

down: ## Stop and remove compose services
	docker compose down

d-migrate: ## Run migrations inside the app container
	docker compose exec app python manage.py migrate

d-collectstatic: ## Collect static files inside the app container
	docker compose exec app python manage.py collectstatic --noinput

d-superuser: ## Create a Django superuser inside the app container
	docker compose exec app python manage.py createsuperuser

d-shell: ## Open a Django shell inside the app container
	docker compose exec app python manage.py shell

# --- housekeeping ------------------------------------------------------------

clean: ## Remove caches and build artifacts
	find . -type d -name "__pycache__" -prune -exec rm -rf {} +
	find . -type d -name ".pytest_cache" -prune -exec rm -rf {} +
	find . -type d -name ".ruff_cache" -prune -exec rm -rf {} +
	find . -type d -name "*.egg-info" -prune -exec rm -rf {} +
	rm -rf build/ dist/ .coverage htmlcov/
