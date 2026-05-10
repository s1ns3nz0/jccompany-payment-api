#!/bin/bash

BASE_URL="http://localhost:8080"
PASS=0
FAIL=0

check() {
    local desc="$1"
    local expected="$2"
    local actual="$3"

    if [ "$actual" = "$expected" ]; then
        echo "✅ PASS | $desc (HTTP $actual)"
        PASS=$((PASS + 1))
    else
        echo "❌ FAIL | $desc (expected $expected, got $actual)"
        FAIL=$((FAIL + 1))
    fi
}

echo "================================================"
echo " JC Company payment-api Integration Tests"
echo "================================================"
echo ""

echo "--- AC-3: Access Control ---"

CODE=$(curl -s -o /dev/null -w "%{http_code}" \
  "$BASE_URL/api/v1/payments")
check "Unauthenticated access blocked" "401" "$CODE"

CODE=$(curl -s -o /dev/null -w "%{http_code}" \
  -X POST "$BASE_URL/api/v1/payments" \
  -u 1001:password1 \
  -H "Content-Type: application/json" \
  -d '{"customerId":1001,"amount":"100.00","currency":"SGD","description":"test payment"}')
check "Authenticated payment creation" "201" "$CODE"

curl -s -X POST "$BASE_URL/api/v1/payments" \
  -u 1002:password2 \
  -H "Content-Type: application/json" \
  -d '{"customerId":1002,"amount":"200.00","currency":"SGD","description":"1002 payment"}' > /dev/null

CODE=$(curl -s -o /dev/null -w "%{http_code}" \
  "$BASE_URL/api/v1/payments/customer/1002" \
  -u 1001:password1)
check "Cross-customer access blocked (AC-3)" "403" "$CODE"

CODE=$(curl -s -o /dev/null -w "%{http_code}" \
  "$BASE_URL/api/v1/payments/customer/1001" \
  -u 1001:password1)
check "Own payment list accessible" "200" "$CODE"

echo ""
echo "--- SI-10: Input Validation ---"

CODE=$(curl -s -o /dev/null -w "%{http_code}" \
  -X POST "$BASE_URL/api/v1/payments" \
  -u 1001:password1 \
  -H "Content-Type: application/json" \
  -d '{"customerId":1001,"amount":"100.00","currency":"sgd","description":"test"}')
check "Lowercase currency rejected" "400" "$CODE"

CODE=$(curl -s -o /dev/null -w "%{http_code}" \
  -X POST "$BASE_URL/api/v1/payments" \
  -u 1001:password1 \
  -H "Content-Type: application/json" \
  -d '{"customerId":1001,"amount":"-100.00","currency":"SGD","description":"test"}')
check "Negative amount rejected" "400" "$CODE"

CODE=$(curl -s -o /dev/null -w "%{http_code}" \
  -X POST "$BASE_URL/api/v1/payments" \
  -u 1001:password1 \
  -H "Content-Type: application/json" \
  -d '{"customerId":1001,"amount":"9999999.00","currency":"SGD","description":"test"}')
check "Amount limit exceeded rejected" "400" "$CODE"

CODE=$(curl -s -o /dev/null -w "%{http_code}" \
  -X POST "$BASE_URL/api/v1/payments" \
  -u 1001:password1 \
  -H "Content-Type: application/json" \
  -d '{"customerId":1001,"amount":"100.00","description":"test"}')
check "Missing currency rejected" "400" "$CODE"

CODE=$(curl -s -o /dev/null -w "%{http_code}" \
  -X POST "$BASE_URL/api/v1/payments" \
  -u 1001:password1 \
  -H "Content-Type: application/json" \
  -d '{"customerId":1001,"amount":"100.00","currency":"SGD","description":"test'\''\" DROP TABLE payments; --"}')
check "SQL injection in description handled safely" "201" "$CODE"

echo ""
echo "--- Actuator ---"

CODE=$(curl -s -o /dev/null -w "%{http_code}" \
  "$BASE_URL/actuator/health")
check "Health endpoint public" "200" "$CODE"

CODE=$(curl -s -o /dev/null -w "%{http_code}" \
  "$BASE_URL/actuator/env")
check "Actuator env endpoint not exposed" "401" "$CODE"

echo ""
echo "================================================"
echo " Results: ✅ $PASS passed | ❌ $FAIL failed"
echo "================================================"
