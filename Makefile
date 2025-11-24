SHELL=/bin/bash -o pipefail

# Application configuration
APP_NAME := chart
DOCKER_REPO := dxas90
REGISTRY := ghcr.io

# Version strategy using git tags
GIT_BRANCH := $(shell git rev-parse --abbrev-ref HEAD)
GIT_TAG := $(shell git describe --exact-match --abbrev=0 2>/dev/null || echo "")
COMMIT_HASH := $(shell git rev-parse --verify HEAD)
COMMIT_TIMESTAMP := $(shell date --date="@$$(git show -s --format=%ct)" --utc +%FT%T)

VERSION := $(shell git describe --tags --always --dirty)
VERSION_STRATEGY := commit_hash

ifdef GIT_TAG
	VERSION := $(GIT_TAG)
	VERSION_STRATEGY := tag
else
	ifeq (,$(findstring $(GIT_BRANCH),main master HEAD))
		ifneq (,$(patsubst release-%,,$(GIT_BRANCH)))
			VERSION := $(GIT_BRANCH)
			VERSION_STRATEGY := branch
		endif
	endif
endif

# Colors for output
RED := \033[31m
GREEN := \033[32m
YELLOW := \033[33m
BLUE := \033[34m
RESET := \033[0m

.PHONY: help install build package test test-coverage test-watch clean run dev run-prod docker-build docker-run docker-compose docker-compose-down k8s-deploy k8s-undeploy helm-deploy helm-test security lint lint-fix format logs monitoring version dev-setup health-check update outdated quick-start full-pipeline release

## Show this help message
help:
	@echo -e "$(BLUE)Available commands:$(RESET)"
	@awk '/^[a-zA-Z\-\_0-9%:\\ ]+:/ { \
		helpMessage = match(lastLine, /^## (.*)/); \
		if (helpMessage) { \
			helpCommand = $$1; \
			helpMessage = substr(lastLine, RSTART + 3, RLENGTH); \
			gsub(":", "", helpCommand); \
			printf "  $(GREEN)%-20s$(RESET) %s\n", helpCommand, helpMessage; \
		} \
	} \
	{ lastLine = $$0 }' $(MAKEFILE_LIST)

## Install dependencies
install:
	@echo -e "$(BLUE)Installing dependencies...$(RESET)"
	@if [ ! -d ".venv" ]; then \
		uv venv .venv; \
	fi
	@uv pip install -r requirements.txt
	@uv pip install -r requirements-dev.txt
	@echo -e "$(GREEN)Dependencies installed successfully$(RESET)"

## Build the application
build: install
	@echo -e "$(BLUE)Building application...$(RESET)"
	@.venv/bin/python -m py_compile app.py
	@echo -e "$(GREEN)Python application ready for execution$(RESET)"

## Package the application for deployment
package: install
	@echo -e "$(BLUE)Packaging application...$(RESET)"
	@uv pip wheel --no-deps -w dist .
	@echo -e "$(GREEN)Application packaged successfully$(RESET)"

## Run tests
test: install
	@echo -e "$(BLUE)Running tests...$(RESET)"
	@.venv/bin/python -m pytest test_app.py -v

## Run tests with coverage
test-coverage: install
	@echo -e "$(BLUE)Running tests with coverage...$(RESET)"
	@.venv/bin/python -m pytest test_app.py -v --cov=app --cov-report=term-missing --cov-report=html

## Run tests in watch mode
test-watch: install
	@echo -e "$(BLUE)Running tests in watch mode...$(RESET)"
	@.venv/bin/python -m pytest-watch test_app.py -v

## Clean build artifacts
clean:
	@echo -e "$(BLUE)Cleaning build artifacts...$(RESET)"
	rm -rf .venv __pycache__ *.pyc .pytest_cache htmlcov coverage.xml .coverage dist build *.egg-info
	@if command -v docker > /dev/null 2>&1; then \
		echo -e "$(BLUE)Cleaning Docker artifacts...$(RESET)"; \
		docker system prune -f || echo -e "$(YELLOW)Warning: Could not clean Docker artifacts$(RESET)"; \
	else \
		echo -e "$(YELLOW)Docker not available, skipping Docker cleanup$(RESET)"; \
	fi

## Run the application locally
run: install
	@echo -e "$(BLUE)Starting application locally...$(RESET)"
	@.venv/bin/python app.py

## Run the application in development mode
dev: install
	@echo -e "$(BLUE)Starting application in development mode...$(RESET)"
	@FLASK_ENV=development FLASK_APP=app.py .venv/bin/flask run --host=0.0.0.0 --port=8000

## Run with production profile
run-prod: install
	@echo -e "$(BLUE)Starting application with production profile...$(RESET)"
	@FLASK_ENV=production .venv/bin/gunicorn app:app -c gunicorn_config.py

## Build Docker image
docker-build:
	@echo -e "$(BLUE)Building Docker image...$(RESET)"
	docker build --target production -t $(APP_NAME):$(VERSION) .
	docker tag $(APP_NAME):$(VERSION) $(APP_NAME):latest

## Run Docker container
docker-run:
	@echo -e "$(BLUE)Running Docker container...$(RESET)"
	docker run -it --rm -p 8000:8000 --name $(APP_NAME) $(APP_NAME):$(VERSION)

## Start application with Docker Compose
docker-compose:
	@echo -e "$(BLUE)Starting services with Docker Compose...$(RESET)"
	@if [ -f "docker-compose.yml" ] || [ -f "docker-compose.yaml" ]; then \
		docker-compose up --build; \
	else \
		echo -e "$(YELLOW)No docker-compose.yml file found$(RESET)"; \
		echo -e "$(YELLOW)Use 'make docker-run' to run the container directly$(RESET)"; \
	fi

## Stop Docker Compose services
docker-compose-down:
	@echo -e "$(BLUE)Stopping Docker Compose services...$(RESET)"
	@if [ -f "docker-compose.yml" ] || [ -f "docker-compose.yaml" ]; then \
		docker-compose down -v; \
	else \
		echo -e "$(YELLOW)No docker-compose.yml file found$(RESET)"; \
	fi

## Deploy to Kubernetes using kubectl
k8s-deploy:
	@echo -e "$(BLUE)Deploying to Kubernetes...$(RESET)"
	@if [ -f "k8s/Chart.yaml" ] || [ -f "k8s/learn-node/Chart.yaml" ]; then \
		echo -e "$(YELLOW)Detected Helm chart. Use 'make helm-deploy' instead$(RESET)"; \
		exit 1; \
	elif [ -d "k8s" ] && [ "$$(find k8s -name '*.yaml' -o -name '*.yml' | grep -v Chart.yaml | wc -l)" -gt 0 ]; then \
		kubectl apply -f k8s/ --recursive; \
	else \
		echo -e "$(YELLOW)No Kubernetes manifests found. Use 'make helm-deploy' for Helm deployment$(RESET)"; \
		exit 1; \
	fi

## Deploy using Helm
helm-deploy:
	@echo -e "$(BLUE)Deploying with Helm...$(RESET)"
	helm upgrade --install $(APP_NAME) ./k8s/chart


## Run helm lint and unit tests for the chart
helm-test:
	@echo -e "$(BLUE)Running helm lint and helm-unittest...$(RESET)"
	@if ! command -v helm > /dev/null 2>&1; then \
		echo -e "$(RED)helm is not installed$(RESET)"; exit 1; \
	fi
	@echo -e "$(BLUE)Linting helm chart...$(RESET)"
	@helm lint k8s/chart || exit 1
	@if ! helm plugin list | grep -q '^unittest'; then \
		echo -e "$(YELLOW)helm-unittest plugin not found. Installing...$(RESET)"; \
		helm plugin install https://github.com/helm-unittest/helm-unittest.git; \
	fi
	@echo -e "$(BLUE)Running helm-unittest...$(RESET)"
	@helm unittest --output-type JUnit --output-file k8s/chart/test-results.xml k8s/chart || exit 1

## Remove Kubernetes deployment
k8s-undeploy:
	@echo -e "$(BLUE)Removing Kubernetes deployment...$(RESET)"
	@if [ -d "k8s" ] && [ "$$(find k8s -name '*.yaml' -o -name '*.yml' | wc -l)" -gt 0 ]; then \
		kubectl delete -f k8s/ --recursive; \
	else \
		echo -e "$(YELLOW)No Kubernetes manifests found in k8s/ directory$(RESET)"; \
		echo -e "$(YELLOW)Use 'helm uninstall $(APP_NAME)' for Helm-based removal$(RESET)"; \
	fi

## Run security scan with Trivy
security:
	@echo -e "$(BLUE)Running security scan...$(RESET)"
	@if command -v trivy > /dev/null 2>&1; then \
		trivy fs --exit-code 1 --severity HIGH,CRITICAL .; \
	else \
		echo -e "$(YELLOW)Trivy not installed, running npm audit instead...$(RESET)"; \
		npm audit --audit-level=high; \
	fi

## Run code quality checks
lint: install
	@echo -e "$(BLUE)Running linters...$(RESET)"
	@.venv/bin/flake8 app.py test_app.py --max-line-length=120

## Fix code quality issues
lint-fix: install
	@echo -e "$(BLUE)Fixing code quality issues...$(RESET)"
	@.venv/bin/autopep8 --in-place --aggressive --aggressive app.py test_app.py

## Format code
format: install
	@echo -e "$(BLUE)Formatting code...$(RESET)"
	@.venv/bin/black app.py test_app.py

## Show application logs
logs:
	@echo -e "$(BLUE)Showing application logs...$(RESET)"
	kubectl logs -l app=$(APP_NAME) --tail=100 -f

## Open monitoring dashboards
monitoring:
	@echo -e "$(BLUE)Opening monitoring dashboards...$(RESET)"
	@echo -e "Prometheus: http://localhost:9090"
	@echo -e "Grafana: http://localhost:3000 (admin/admin)"
	@echo -e "Application: http://localhost:3000"
	@echo -e "Health Check: http://localhost:3000/healthz"

## Show version information
version:
	@echo -e "$(BLUE)Version Information:$(RESET)"
	@echo -e "Version: $(VERSION)"
	@echo -e "Strategy: $(VERSION_STRATEGY)"
	@echo -e "Git Tag: $(GIT_TAG)"
	@echo -e "Git Branch: $(GIT_BRANCH)"
	@echo -e "Commit Hash: $(COMMIT_HASH)"
	@echo -e "Commit Timestamp: $(COMMIT_TIMESTAMP)"

## Setup development environment
dev-setup:
	@echo -e "$(BLUE)Setting up development environment...$(RESET)"
	@echo -e "Installing dependencies..."
	npm install
	@echo -e "Setting up git hooks..."
	# Add pre-commit hooks setup here if needed
	@echo -e "$(GREEN)Development environment ready!$(RESET)"

## Health check
health-check:
	@echo -e "$(BLUE)Performing health check...$(RESET)"
	@curl -s http://localhost:8000/healthz | jq . || echo -e "$(RED)Health check failed$(RESET)"

## Update dependencies
update:
	@echo -e "$(BLUE)Updating dependencies...$(RESET)"
	@uv pip install --upgrade -r requirements.txt
	@.venv/bin/pip-audit || true

## Check for outdated packages
outdated:
	@echo -e "$(BLUE)Checking for outdated packages...$(RESET)"
	@uv pip list --outdated || true

## Quick start - install, test, and run locally
quick-start: clean install test run

## Full pipeline - test, build, and deploy locally
full-pipeline: test security docker-build docker-compose

## Release - tag and build for release
release:
	@echo -e "$(BLUE)Preparing release $(VERSION)...$(RESET)"
	git tag -a v$(VERSION) -m "Release version $(VERSION)"
	$(MAKE) docker-build
	@echo -e "$(GREEN)Release $(VERSION) ready!$(RESET)"
