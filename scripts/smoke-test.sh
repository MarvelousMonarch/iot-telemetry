#!/usr/bin/env bash
set -euo pipefail

echo "=== Running Smoke Tests (chart) ==="

RELEASE_NAME="chart"
NAMESPACE="default"

echo "Checking if deployment exists..."
kubectl get deployment -l app.kubernetes.io/instance=${RELEASE_NAME} -n ${NAMESPACE}

echo "Checking if pods are running..."
PODS=$(kubectl get pods -n ${NAMESPACE} -l app.kubernetes.io/instance=${RELEASE_NAME} --field-selector=status.phase=Running --no-headers | wc -l)
if [ "$PODS" -eq 0 ]; then
    echo "❌ No running pods found for ${RELEASE_NAME}"
    kubectl get pods -n ${NAMESPACE} -l app.kubernetes.io/instance=${RELEASE_NAME}
    exit 1
fi
echo "✅ Found $PODS running pod(s)"

SERVICE_NAME=$(kubectl get svc -l app.kubernetes.io/instance=${RELEASE_NAME} -n ${NAMESPACE} -o jsonpath='{.items[0].metadata.name}')
echo "Using service: ${SERVICE_NAME}"

echo "Waiting for pods to be ready..."
kubectl wait --for=condition=Ready pod -l app.kubernetes.io/instance=${RELEASE_NAME} -n ${NAMESPACE} --timeout=300s

POD_NAME=$(kubectl get pods -n ${NAMESPACE} -l app.kubernetes.io/instance=${RELEASE_NAME} -o jsonpath='{.items[0].metadata.name}')
echo "Testing health endpoint via in-pod Python request (pod: ${POD_NAME})..."
kubectl exec -n ${NAMESPACE} ${POD_NAME} -- python - <<PY
import sys, urllib.request
resp = urllib.request.urlopen('http://localhost:8000/healthz', timeout=5)
print(resp.read().decode())
if resp.getcode() != 200:
    sys.exit(1)
PY

echo "=== Smoke Tests Passed ==="
