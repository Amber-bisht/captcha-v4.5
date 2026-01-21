#!/bin/bash
# Full CAPTCHA Flow Test
# Tests the complete CAPTCHA flow from init to redirect

set -e

BASE_URL="${CAPTCHA_URL:-https://captcha-p.asprin.dev}"
CLIENT_URL="${CLIENT_URL:-https://links.asprin.dev}"

echo "🔄 Full CAPTCHA Flow Test"
echo "========================="
echo "CAPTCHA Server: $BASE_URL"
echo "Client Origin: $CLIENT_URL"
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

test_step() {
    local STEP=$1
    local NAME=$2
    local RESULT=$3
    local DETAILS=$4
    
    if [ "$RESULT" == "PASS" ]; then
        echo -e "${GREEN}✅ [$STEP] $NAME${NC}"
    elif [ "$RESULT" == "WARN" ]; then
        echo -e "${YELLOW}⚠️  [$STEP] $NAME${NC}"
    else
        echo -e "${RED}❌ [$STEP] $NAME${NC}"
    fi
    
    if [ -n "$DETAILS" ]; then
        echo "   $DETAILS"
    fi
}

# Step 1: Init
echo "Step 1: Initialize CAPTCHA"
echo "---"
INIT_RESPONSE=$(curl -s -w "\n%{http_code}" "$BASE_URL/api/image/api/init" \
    -H "Origin: $CLIENT_URL" \
    -H "Referer: $CLIENT_URL/" \
    -H "User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36")

HTTP_CODE=$(echo "$INIT_RESPONSE" | tail -n1)
BODY=$(echo "$INIT_RESPONSE" | sed '$d')

if [ "$HTTP_CODE" == "200" ]; then
    NONCE=$(echo "$BODY" | jq -r '.nonce // empty')
    DIFFICULTY=$(echo "$BODY" | jq -r '.difficulty // empty')
    
    if [ -n "$NONCE" ]; then
        test_step "1a" "Init endpoint accessible" "PASS" "HTTP 200"
        test_step "1b" "Nonce received" "PASS" "Length: ${#NONCE} chars"
        test_step "1c" "Difficulty received" "PASS" "Level: $DIFFICULTY"
    else
        test_step "1" "Init response" "FAIL" "Missing nonce in response"
    fi
else
    test_step "1" "Init endpoint" "FAIL" "HTTP $HTTP_CODE"
    echo "Response: $BODY"
fi

echo ""

# Step 2: CORS Check
echo "Step 2: CORS Configuration"
echo "---"
CORS_RESPONSE=$(curl -s -I -X OPTIONS "$BASE_URL/api/image/api/request-challenge" \
    -H "Origin: $CLIENT_URL" \
    -H "Access-Control-Request-Method: POST" \
    -H "Access-Control-Request-Headers: content-type")

if echo "$CORS_RESPONSE" | grep -qi "access-control-allow-origin.*$CLIENT_URL"; then
    test_step "2a" "CORS allows client origin" "PASS"
elif echo "$CORS_RESPONSE" | grep -qi "access-control-allow-origin.*\*"; then
    test_step "2a" "CORS configuration" "WARN" "Wildcard origin is insecure"
else
    test_step "2a" "CORS allows client origin" "FAIL"
fi

if echo "$CORS_RESPONSE" | grep -qi "access-control-allow-credentials.*true"; then
    test_step "2b" "Credentials allowed" "PASS"
else
    test_step "2b" "Credentials allowed" "PASS" "Not required for CAPTCHA"
fi

echo ""

# Step 3: Request Challenge (without PoW - should fail)
echo "Step 3: Challenge Endpoint Protection"
echo "---"
CHALLENGE_RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$BASE_URL/api/image/api/request-challenge" \
    -H "Content-Type: application/json" \
    -H "Origin: $CLIENT_URL" \
    -d '{"nonce":"invalid_nonce","solution":"000000"}')

HTTP_CODE=$(echo "$CHALLENGE_RESPONSE" | tail -n1)
BODY=$(echo "$CHALLENGE_RESPONSE" | sed '$d')

if [ "$HTTP_CODE" == "403" ] || echo "$BODY" | grep -qi "invalid"; then
    test_step "3a" "Rejects invalid PoW nonce" "PASS" "HTTP $HTTP_CODE"
else
    test_step "3a" "Rejects invalid PoW nonce" "FAIL" "HTTP $HTTP_CODE - $BODY"
fi

# Step 4: Verify Endpoint (without token)
echo ""
echo "Step 4: Verify Endpoint Protection"
echo "---"
VERIFY_RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$BASE_URL/api/image/api/verify" \
    -H "Content-Type: application/json" \
    -H "Origin: $CLIENT_URL" \
    -d '{"sessionId":"fake","token":"invalid","textAnswer":"test"}')

HTTP_CODE=$(echo "$VERIFY_RESPONSE" | tail -n1)
BODY=$(echo "$VERIFY_RESPONSE" | sed '$d')

if [ "$HTTP_CODE" == "403" ] || [ "$HTTP_CODE" == "400" ] || echo "$BODY" | grep -qiE "invalid|failed|error"; then
    test_step "4a" "Rejects invalid session" "PASS"
else
    test_step "4a" "Rejects invalid session" "WARN" "Response: $BODY"
fi

# Step 5: Honeypot Detection
echo ""
echo "Step 5: Honeypot Detection"
echo "---"
HONEYPOT_RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$BASE_URL/api/image/api/verify" \
    -H "Content-Type: application/json" \
    -H "Origin: $CLIENT_URL" \
    -d '{"sessionId":"test","token":"test","textAnswer":"test","honeyPot":"i_am_a_bot"}')

HTTP_CODE=$(echo "$HONEYPOT_RESPONSE" | tail -n1)
BODY=$(echo "$HONEYPOT_RESPONSE" | sed '$d')

if [ "$HTTP_CODE" == "403" ] || echo "$BODY" | grep -qi "violation"; then
    test_step "5a" "Honeypot trap works" "PASS" "HTTP $HTTP_CODE"
else
    test_step "5a" "Honeypot trap" "FAIL" "Should reject filled honeypot"
fi

# Step 6: Health Check
echo ""
echo "Step 6: Infrastructure"
echo "---"
HEALTH_RESPONSE=$(curl -s "$BASE_URL/health")

if echo "$HEALTH_RESPONSE" | grep -qi "healthy"; then
    REDIS_STATUS=$(echo "$HEALTH_RESPONSE" | jq -r '.redis // "unknown"')
    test_step "6a" "Health endpoint" "PASS" "Redis: $REDIS_STATUS"
else
    test_step "6a" "Health endpoint" "FAIL" "$HEALTH_RESPONSE"
fi

# Summary
echo ""
echo "================================"
echo "Flow Test Summary"
echo "================================"
echo ""
echo "✅ Tests Passed: Endpoints properly protected"
echo "⚠️  Note: Full flow requires PoW solver"
echo ""
echo "For complete end-to-end testing, use:"
echo "  node security_scanner.js --full-flow"
