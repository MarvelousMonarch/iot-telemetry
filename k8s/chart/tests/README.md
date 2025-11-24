# Helm Unit Tests — chart Chart

This directory contains unit tests for the `chart` Helm chart using the `helm-unittest` plugin.

These tests assert the chart templates render as expected under a variety of value overrides and conditional logic. They are fast, local unit tests used to validate template logic and resource defaults.

## Requirements

- Helm v3
- helm-unittest plugin

Install the plugin (one-time):

```bash
helm plugin install https://github.com/helm-unittest/helm-unittest.git
```

Verify installation with:

```bash
helm plugin list
```

## Common Commands

- Run all tests from the repository root:

```bash
helm unittest k8s/chart
```

- Run all helm chart tests using Makefile (from repo root):

```bash
make helm-test
```

- Run tests from inside the chart directory:

```bash
cd k8s/chart
helm unittest .
```

- Run a single test file (examples):

```bash
helm unittest -f 'tests/deployment_test.yaml' k8s/chart
helm unittest -f 'tests/service_test.yaml' k8s/chart
```

- Run in debug mode (verbose rendering):

```bash
helm unittest -d k8s/chart
```

- Generate JUnit report for CI:

```bash
helm unittest --output-type JUnit --output-file test-results.xml k8s/chart
```

## Test structure

Tests are organized into YAML files that follow the `helm-unittest` format. Each file contains one or more suites. Example files in this folder:

- `deployment_test.yaml` - tests for `templates/deployment.yaml`
- `service_test.yaml` - tests for `templates/service.yaml`
- `hpa_test.yaml` - tests for `templates/hpa.yaml` (autoscaling)
- `pvc_test.yaml` - tests for `templates/pvc.yaml` (persistence)
- `configmap_test.yaml` - tests for `templates/configmap.yaml`
- `httproute_test.yaml` - tests for `templates/httproute.yaml` (Gateway API)
- `networkpolicy_test.yaml` - tests for `templates/networkpolicy.yaml`

Each test path contains:

- `suite` (human-friendly name)
- `templates` to load and assert on
- `tests` with `set:` overrides and `asserts:` statements

Example (short):

```yaml
suite: test deployment
templates:
  - deployment.yaml
tests:
  - it: should set custom image tag
    set:
      image.tag: v1.0.0
    asserts:
      - equal:
          path: spec.template.spec.containers[0].image
          value: ghcr.io/dxas90/chart:v1.0.0
```

## Common assertion types

- `isKind` — check Kubernetes object kind
- `equal` — assert equality at the JSONPath
- `contains` — assert presence of item in a list or map
- `isNull` / `isNotNull` — presence check
- `isSubset` — partial map matching
- `hasDocuments` — assert YAML document count

- For a full list, see the [helm-unittest documentation](https://github.com/helm-unittest/helm-unittest)


## Best practices

- Keep tests focused — one behavior per test.
- Use `set:` in tests to clearly show the value override being tested.
- Match test expectations to the chart `values.yaml` defaults.
- Update tests when you change `templates` or default values.

## CI Integration

You can run the `helm unittest` command inside your CI pipeline to fail fast on template regressions. Example GitHub Actions step:

```yaml
- name: Install helm-unittest
  run: helm plugin install https://github.com/helm-unittest/helm-unittest.git

- name: Run Helm Unit Tests
  run: helm unittest k8s/chart --output-type JUnit --output-file test-results.xml

- name: Publish Test Results
  uses: EnricoMi/publish-unit-test-result-action@v2
  if: always()
  with:
    files: test-results.xml
```


## Troubleshooting

- `Plugin not found`: install or update helm-unittest.
- `YAML parse errors`: check test YAML formatting and indentation.
- `Assertion failures`: check `helm unittest -d` to render the templates and compare actual vs expected.

If you want, I can add an example `Makefile` target to run these tests. Want that added?
