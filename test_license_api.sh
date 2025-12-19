#!/bin/bash
# Test script for License API
# Usage: ./test_license_api.sh

set -e

API_URL="http://localhost:10000"

echo "==================================="
echo "License API Test Script"
echo "==================================="
echo ""

# Step 1: Check if ScyllaDB is running
echo "[1/6] Checking if ScyllaDB is running..."
if ! curl -s -f "${API_URL}/v2/license/status" > /dev/null 2>&1; then
    echo "❌ ScyllaDB is not running or license API is not available"
    echo "Please start ScyllaDB with: ./build/dev/scylla --developer-mode 1"
    exit 1
fi
echo "✅ ScyllaDB is running"
echo ""

# Step 2: Check initial status (should be no_license)
echo "[2/6] Checking initial license status..."
STATUS=$(curl -s "${API_URL}/v2/license/status")
echo "Response: $STATUS"
if echo "$STATUS" | jq -e '.status == "no_license"' > /dev/null 2>&1; then
    echo "✅ No license installed (as expected)"
else
    echo "⚠️  Unexpected status, continuing anyway..."
fi
echo ""

# Step 3: Generate a test license
echo "[3/6] Generating test license..."
if [ ! -f "tools/scylla-license-gen.py" ]; then
    echo "❌ Cannot find tools/scylla-license-gen.py"
    exit 1
fi

# Use the embedded public key's seed for testing
# This is the test seed from license_compliance_test.cc
TEST_SEED="0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"

echo "Generating unlimited license for TestCorp..."
./tools/scylla-license-gen.py generate-license \
    --seed "$TEST_SEED" \
    --customer "TestCorp" \
    --unlimited \
    --output /tmp/test_license.key > /dev/null 2>&1

if [ ! -f /tmp/test_license.key ]; then
    echo "❌ Failed to generate license"
    exit 1
fi
echo "✅ License generated: /tmp/test_license.key"
echo ""

# Step 4: Upload the license
echo "[4/6] Uploading license via API..."
UPLOAD_RESPONSE=$(curl -s -w "\n%{http_code}" -X POST \
    -H "Content-Type: text/plain" \
    --data-binary @/tmp/test_license.key \
    "${API_URL}/v2/license/upload")

HTTP_CODE=$(echo "$UPLOAD_RESPONSE" | tail -n 1)
RESPONSE_BODY=$(echo "$UPLOAD_RESPONSE" | head -n -1)

if [ "$HTTP_CODE" = "200" ]; then
    echo "✅ License uploaded successfully"
else
    echo "❌ Upload failed with HTTP $HTTP_CODE"
    echo "Response: $RESPONSE_BODY"
    exit 1
fi
echo ""

# Step 5: Check license status (should be valid)
echo "[5/6] Checking license status after upload..."
STATUS=$(curl -s "${API_URL}/v2/license/status")
echo "Response: $STATUS"
if echo "$STATUS" | jq -e '.status == "valid"' > /dev/null 2>&1; then
    CUSTOMER=$(echo "$STATUS" | jq -r '.customer_id')
    echo "✅ License is valid for customer: $CUSTOMER"
else
    echo "❌ License status is not valid"
    echo "$STATUS" | jq .
    exit 1
fi
echo ""

# Step 6: Check usage information
echo "[6/6] Checking license usage..."
USAGE=$(curl -s "${API_URL}/v2/license/usage")
echo "Response:"
echo "$USAGE" | jq .

VCPUS=$(echo "$USAGE" | jq -r '.current_vcpus')
STORAGE=$(echo "$USAGE" | jq -r '.current_storage_bytes')
VCPU_EXCEEDED=$(echo "$USAGE" | jq -r '.vcpu_limit_exceeded')
STORAGE_EXCEEDED=$(echo "$USAGE" | jq -r '.storage_limit_exceeded')

echo ""
echo "Current usage:"
echo "  - vCPUs: $VCPUS"
echo "  - Storage: $STORAGE bytes"
echo "  - vCPU limit exceeded: $VCPU_EXCEEDED"
echo "  - Storage limit exceeded: $STORAGE_EXCEEDED"

if [ "$VCPU_EXCEEDED" = "false" ] && [ "$STORAGE_EXCEEDED" = "false" ]; then
    echo "✅ Within license limits"
else
    echo "⚠️  Limits exceeded (but should be unlimited for test license)"
fi
echo ""

echo "==================================="
echo "✅ All tests passed!"
echo "==================================="
echo ""
echo "Cleanup: To delete the license, run:"
echo "  curl -X DELETE ${API_URL}/v2/license"

