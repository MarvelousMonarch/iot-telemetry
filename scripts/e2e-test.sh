#!/bin/bash
set -e

echo "=== Running End-to-End Tests ==="

RELEASE_NAME="chart"
NAMESPACE="default"
SERVICE_PORT=8000

# Get pod and service names
POD_NAME=$(kubectl get pods -n ${NAMESPACE} -l app.kubernetes.io/instance=${RELEASE_NAME} -o jsonpath='{.items[0].metadata.name}')
SERVICE_NAME=$(kubectl get svc -l app.kubernetes.io/instance=${RELEASE_NAME} -n ${NAMESPACE} -o jsonpath='{.items[0].metadata.name}')
echo "Testing pod: $POD_NAME"

echo "--- Test 1: Health Endpoint ---"
HEALTH_RESPONSE=$(kubectl exec -n ${NAMESPACE} ${POD_NAME} -- /usr/local/bin/python -c "
import sys, urllib.request
try:
    resp = urllib.request.urlopen('http://localhost:8000/healthz', timeout=5)
    body = resp.read().decode()
    print(body)
    if resp.getcode() != 200:
        print('Status code:', resp.getcode())
        sys.exit(1)
except Exception as e:
    print('Error:', str(e))
    sys.exit(1)
")
EXIT_CODE=$?
if [ $EXIT_CODE -ne 0 ]; then
    echo "❌ Health endpoint test failed"
    echo "Response: $HEALTH_RESPONSE"
    exit 10
fi

if [[ "$HEALTH_RESPONSE" == *"healthy"* ]]; then
    echo "✅ Health endpoint test passed"
else
    echo "❌ Health endpoint test failed"
    echo "Response: $HEALTH_RESPONSE"
    exit 10
fi

echo "--- Test 2: Root Endpoint ---"
ROOT_RESPONSE=$(kubectl exec -n ${NAMESPACE} ${POD_NAME} -- /usr/local/bin/python -c "
import urllib.request, sys
resp = urllib.request.urlopen('http://localhost:8000/', timeout=5)
print(resp.read().decode())
if resp.getcode() != 200:
    sys.exit(1)
")
EXIT_CODE=$?
if [ $EXIT_CODE -ne 0 ]; then
    echo "❌ Root endpoint test failed"
    exit 11
fi

if [[ ! -z "$ROOT_RESPONSE" ]]; then
    echo "✅ Root endpoint test passed"
else
    echo "❌ Root endpoint test failed"
    exit 11
fi

echo "--- Test 3: Service Connectivity ---"
# Test that the service is accessible within the cluster
SERVICE_IP=$(kubectl get service ${SERVICE_NAME} -n ${NAMESPACE} -o jsonpath='{.spec.clusterIP}')
echo "Service IP: $SERVICE_IP"

# Test service connectivity via in-pod Python request
if ! kubectl exec -n ${NAMESPACE} ${POD_NAME} -- /usr/local/bin/python -c "import sys, urllib.request; resp = urllib.request.urlopen('http://${SERVICE_NAME}.${NAMESPACE}.svc.cluster.local:8000/healthz', timeout=5); body=resp.read().decode(); print(body); sys.exit(0 if resp.getcode()==200 else 1)"; then
    echo "❌ Service connectivity test failed"
    exit 12
fi
echo "✅ Service connectivity test passed"

echo "--- Test 4: Pod Resilience ---"
INITIAL_POD_COUNT=$(kubectl get pods -n ${NAMESPACE} -l app.kubernetes.io/instance=${RELEASE_NAME} --field-selector=status.phase=Running --no-headers | wc -l)
echo "Initial pod count: $INITIAL_POD_COUNT"

echo "Deleting a pod to test resilience..."
kubectl delete pod ${POD_NAME} -n ${NAMESPACE}

echo "Waiting for replacement pod to be ready..."
sleep 5
kubectl wait --for=condition=Ready pod -l app.kubernetes.io/instance=${RELEASE_NAME} -n ${NAMESPACE} --timeout=120s

FINAL_POD_COUNT=$(kubectl get pods -n ${NAMESPACE} -l app.kubernetes.io/instance=${RELEASE_NAME} --field-selector=status.phase=Running --no-headers | wc -l)
if [ "$FINAL_POD_COUNT" -eq "$INITIAL_POD_COUNT" ]; then
    echo "✅ Pod resilience test passed"
else
    echo "❌ Pod resilience test failed (Expected: $INITIAL_POD_COUNT, Got: $FINAL_POD_COUNT)"
    exit 13
fi

echo "--- Test 5: Resource Limits ---"
echo "Verifying resource limits are set..."
DEPLOYMENT_NAME=$(kubectl get deployment -n ${NAMESPACE} -l app.kubernetes.io/instance=${RELEASE_NAME} -o jsonpath='{.items[0].metadata.name}')
RESOURCE_LIMITS=$(kubectl get deployment ${DEPLOYMENT_NAME} -n ${NAMESPACE} -o jsonpath='{.spec.template.spec.containers[0].resources.limits}')
if [[ ! -z "$RESOURCE_LIMITS" ]]; then
    echo "✅ Resource limits configured: $RESOURCE_LIMITS"
else
    echo "⚠️  No resource limits configured"
fi

echo "=== All E2E Tests Passed ==="
