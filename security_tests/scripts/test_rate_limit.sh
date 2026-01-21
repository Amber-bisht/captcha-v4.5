#!/bin/bash
# Rate Limiting Test
# Tests rate limiting on CAPTCHA endpoints

set -e

BASE_URL="${CAPTCHA_URL:-https://captcha-p.asprin.dev}"
CLIENT_URL="${CLIENT_URL:-https://links.asprin.dev}"

echo "🚦 Rate Limiting Test"
echo "====================="
echo "Target: $BASE_URL"
echo ""

# Configuration from your server
CHALLENGE_LIMIT=20  # 20 per hour
VERIFY_LIMIT=120    # 120 per hour

echo "Expected Limits:"
echo "  - Challenge endpoint: $CHALLENGE_LIMIT req/hour"
echo "  - Verify endpoint: $VERIFY_LIMIT req/hour"
echo ""

# Test 1: Init endpoint rate limit
echo "[Test 1] Testing /api/init endpoint..."
echo "Sending 25 requests rapidly..."

SUCCESS_COUNT=0
BLOCKED_COUNT=0

for i in {1..25}; do
    RESPONSE=$(curl -s -w "\n%{http_code}" -X GET "$BASE_URL/api/image/api/init" \
        -H "Origin: $CLIENT_URL" \
        -H "Referer: $CLIENT_URL/" \
        -H "User-Agent: Mozilla/5.0" 2>/dev/null)
    
    HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
    BODY=$(echo "$RESPONSE" | sed '$d')
    
    if [ "$HTTP_CODE" == "200" ]; then
        ((SUCCESS_COUNT++))
    elif [ "$HTTP_CODE" == "429" ]; then
        ((BLOCKED_COUNT++))
        echo "  Request $i: BLOCKED (429)"
    else
        echo "  Request $i: HTTP $HTTP_CODE"
    fi
done

echo ""
echo "Results:"
echo "  ✅ Successful: $SUCCESS_COUNT"
echo "  🚫 Blocked (429): $BLOCKED_COUNT"
echo ""

if [ $BLOCKED_COUNT -gt 0 ]; then
    echo "✅ Rate limiting is ACTIVE on init endpoint"
else
    echo "⚠️  Rate limiting may not be properly configured"
    echo "    (25 requests all succeeded)"
fi

# Test 2: Challenge endpoint header check
echo ""
echo "[Test 2] Checking rate limit headers..."
RESPONSE=$(curl -s -I -X GET "$BASE_URL/api/image/api/init" \
    -H "Origin: $CLIENT_URL" \
    -H "Referer: $CLIENT_URL/" 2>/dev/null)

echo "$RESPONSE" | grep -i "ratelimit" || echo "No rate limit headers found"

# Test 3: IP-based vs fingerprint-based
echo ""
echo "[Test 3] Rate limit scope analysis..."
echo "Checking if rate limit is per-IP or per-fingerprint..."

# First IP
RESPONSE1=$(curl -s -X GET "$BASE_URL/api/image/api/init" \
    -H "Origin: $CLIENT_URL" \
    -H "X-Forwarded-For: 1.2.3.4" 2>/dev/null)

# Second IP
RESPONSE2=$(curl -s -X GET "$BASE_URL/api/image/api/init" \
    -H "Origin: $CLIENT_URL" \
    -H "X-Forwarded-For: 5.6.7.8" 2>/dev/null)

if [ -n "$RESPONSE1" ] && [ -n "$RESPONSE2" ]; then
    echo "  Different X-Forwarded-For IPs both received responses"
    echo "  ⚠️  Check if proxy headers are trusted"
fi

echo ""
echo "📋 Manual Test Instructions:"
echo "1. Run this script from different IP addresses"
echo "2. Monitor Redis keys: captcha:rate_limit:*"
echo "3. Verify rate limits reset after window expires"
echo ""
echo "Rate Limit Test Complete."
