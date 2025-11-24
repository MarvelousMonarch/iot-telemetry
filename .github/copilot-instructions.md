# AI Coding Assistant — chart (concise guide)

This file gives a short, focused summary for AI coding agents to be productive on the chart repository.

Overview
- This repo contains a small Flask microservice (app.py), unit tests (test_app.py), a Docker image, and a Helm chart under `k8s/chart` for Kubernetes deployment.
- The service exposes 6 key endpoints: `/`, `/ping`, `/healthz`, `/info`, `/version`, `/echo` and is designed to be small and demonstrative.

High-level architecture and responsibilities
- app.py: Flask app with handlers and middleware for security headers and logging. Keep business logic small — it’s a learning microservice.
- tests (unit): `test_app.py` — uses Python unittest against Flask test_client.
- k8s/chart: Helm v2/v3 Chart with function helpers in `templates/_helpers.tpl`. Templates include Deployment, Service, HTTPRoute, HPA, PVC, NetworkPolicy.
- Chart values are managed by `k8s/chart/values.yaml`. Key toggles: `autoscaling.enabled`, `persistence.enabled`, `httproute.enabled`, `service.port`.

Key files and where to look
- `app.py` — main endpoints and security middleware.
- `test_app.py` — Python unit tests for endpoints.
- `Makefile` — common commands: `make dev` (Run server with Flask), `make test` (pytest), `make helm-test` (helm lint + helm-unittest), and `make docker-build`.
- `k8s/chart/` — Helm chart, contains templates, values.yaml, and `tests/` directory with helm-unittest suites.
- `k8s/chart/templates/_helpers.tpl` — helper templates for names and labels. Use these in new resources.

Important conventions and patterns
- Labeling: Chart uses standard labels via the helper `base.labels` (which includes `app.kubernetes.io/part-of: "chart"`). Add new resources that follow this helper for consistent labeling.
- Naming: Use `include \"base.fullname\"` and `include \"base.name\"` for resource names.
- Toggle resources through `values.yaml` booleans. Examples:
  - `autoscaling.enabled`: controls HPA render.
  - `persistence.enabled`: controls PVC rendering and volume mounts in Deployment.
  - `httproute.enabled`: controls HTTPRoute creation.
- Use `toYaml` + `nindent` for safe multiline embedding (labels, annotations, envFrom, volumes).
- Probes: Liveness and readiness definitions are defined in `values.yaml` and used by `{{- with .Values.livenessProbe }}` in templates. Use them rather than inlining.

Testing and CI
- Unit tests for the service: `make test` runs `pytest` against `test_app.py`. The Makefile's `install` target prepares a `.venv` using the `uv` wrapper defined by `mise.toml`.
  - Note: run `make install` first to ensure `.venv` and `pytest` are installed, or add `python -m pip install -r requirements-dev.txt` if needed.
  - Note: tests (and the app middleware) check `FLASK_ENV` - set `FLASK_ENV=test` (or set in tests) to suppress request logs when running unit tests.
- Helm tests: `make helm-test` runs `helm lint` and `helm-unittest` (plugin). Tests live in `k8s/chart/tests/*.yaml` and use `set:` and `asserts:` to verify rendered manifests.
- `helm-unittest` assertions rely on the `path:` JSON path. Use `hasDocuments` to assert presence/absence of a template when a feature is disabled.
- CI note: The repository contains a `full-workflow.yml` in `.github/workflows/` that includes a helm test step — validate the job references `k8s/chart` (old entries reference `k8s/learn-node`). Update CI for this chart where necessary.
- CI note: The repository contains a `full-workflow.yml` in `.github/workflows/` that includes helm unittest + lint and a Kind test-deployment flow. Recent updates convert the workflow to Python-first (lint/test/security) and multi-arch Docker builds; CI now:
  - Uses a Python test matrix (3.11/3.12/3.13) with an isolated `.venv` created via `uv`.
  - Lints with `flake8` + `black` and runs tests with `pytest` + `pytest-cov`.
  - Runs `pip-audit` for Python vulnerabilities and Trivy for Docker image scanning.
  - Builds Docker images with Buildx, exports an image artifact for Kind testing, and runs helm lint + helm-unittest against `k8s/chart`.
  - The `test-deployment` job loads the artifact into Kind, Helm-installs `k8s/chart` (image tagged `test`), and runs smoke and e2e verifications using in-cluster curl containers and a port-forwarded client. Scripts were updated to use `chart` and port 8000.
  - The workflow also uploads test artifacts (coverage, helm junit) and Trivy results for auditing and CI visibility.

Developer workflows (quick commands)
- Run locally in dev: `make dev` (starts Flask app on port 8000)
- Run unit tests: `make test` or `pytest test_app.py` with `FLASK_ENV=test` to quiet logs
- Build and run Docker: `make docker-build && make docker-run`
- Lint Helm and run Helm unit tests: `make helm-test` (requires `helm` and `helm-unittest` plugin)
- Run helm tests debug mode: `helm unittest -d k8s/chart` (shows rendered YAML to inspect)

AI agent patterns to follow
- Keep functions small, side-effect free and testable (prefers `app.py` small handlers — create helper functions under `lib/` or `src/` if new logic grows).
- When modifying template labels, update `templates/_helpers.tpl` or use `include "base.labels"` — then update matching unit tests.
- When changing `values.yaml` defaults, update Helm tests in `k8s/chart/tests/` accordingly.
- Add new chart templates with conditional flags (e.g., `{{- if .Values.featureX.enabled }}`) to keep resources optional.
- Add `helm-unittest` tests whenever changing resources or toggles; tests must reflect actual rendered output.

Troubleshooting and tips
- If a helm unit test fails, re-run with `-d` to inspect rendered YAML and update expectations.
- Use `helm include` helpers to reuse names/labels and to avoid breaking selectors accidentally.
- For new environment variables used in the app, add them to the Helm Chart's `values.yaml` and update `templates/configmap.yaml` or `envFrom` accordingly.
- When adding Pod-level changes (securityContext, resources), mirror them in tests for deployment resource assertions.

If anything here is unclear, say which part you want expanded (e.g., more Helm test examples, `Makefile` patterns, or a path-based list of key files to use for PR checks).
