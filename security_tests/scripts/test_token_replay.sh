#!/bin/bash
# Token Replay Attack Test
# Tests if CAPTCHA tokens can be reused after first use

set -e

BASE_URL="${CAPTCHA_URL:-https://captcha-p.asprin.dev}"
CLIENT_URL="${CLIENT_URL:-https://links.asprin.dev}"

echo "🔐 Token Replay Attack Test"
echo "============================"
echo "Target: $BASE_URL"
echo ""

# Step 1: Initialize and get PoW challenge
echo "[1/5] Getting PoW challenge..."
INIT_RESPONSE=$(curl -s -X GET "$BASE_URL/api/image/api/init" \
    -H "Origin: $CLIENT_URL" \
    -H "Referer: $CLIENT_URL/" \
    -H "User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36")

echo "Init Response: $INIT_RESPONSE"

NONCE=$(echo $INIT_RESPONSE | jq -r '.nonce')
DIFFICULTY=$(echo $INIT_RESPONSE | jq -r '.difficulty')

if [ "$NONCE" == "null" ] || [ -z "$NONCE" ]; then
    echo "❌ Failed to get nonce"
    exit 1
fi

echo "Nonce: $NONCE"
echo "Difficulty: $DIFFICULTY"

# Step 2: Solve PoW (simplified - real test would compute hash)
echo ""
echo "[2/5] Solving Proof-of-Work..."
echo "⚠️  Note: This test requires manual PoW solution or a PoW solver"
echo "    For automated testing, use the Node.js version"
echo ""

# For demonstration, we'll attempt with a dummy solution
# In real test, you'd compute: SHA256(nonce + counter).startsWith('0'.repeat(difficulty))

# Step 3: Request challenge
echo "[3/5] Requesting CAPTCHA challenge..."
echo "⚠️  Skipping due to PoW requirement"
echo ""

# Step 4 & 5: Token reuse test
echo "[4/5] Testing Token Reuse Detection..."
echo ""
echo "To complete this test manually:"
echo "1. Capture a valid captchaToken from browser DevTools"
echo "2. Use it in the first verification request"
echo "3. Try to reuse the same token"
echo ""

# Test if token endpoint blocks reused tokens
echo "[5/5] Expected behavior:"
echo "  - First use: ✅ 200 OK with success"
echo "  - Second use: ❌ 403 or error (token already used)"
echo ""

echo "📋 Test Script Template for Token Reuse:"
cat << 'EOF'

# After capturing a valid token:
VALID_TOKEN="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...."

# First verification (should succeed if answer is correct)
curl -X POST "$BASE_URL/api/image/api/verify" \
    -H "Content-Type: application/json" \
    -H "Origin: $CLIENT_URL" \
    -d '{
        "sessionId": "YOUR_SESSION_ID",
        "token": "'$VALID_TOKEN'",
        "textAnswer": "YOUR_ANSWER",
        "honeyPot": ""
    }'

# Second verification with same token (should fail)
curl -X POST "$BASE_URL/api/image/api/verify" \
    -H "Content-Type: application/json" \
    -H "Origin: $CLIENT_URL" \
    -d '{
        "sessionId": "YOUR_SESSION_ID",
        "token": "'$VALID_TOKEN'",
        "textAnswer": "YOUR_ANSWER",
        "honeyPot": ""
    }'

# ✅ PASS: Second request returns error
# ❌ FAIL: Second request also succeeds

EOF

echo ""
echo "Test completed. See security_scanner.js for automated testing."
