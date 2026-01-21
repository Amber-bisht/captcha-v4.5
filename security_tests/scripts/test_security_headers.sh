#!/bin/bash
# Security Headers Test
# Verifies security headers are properly configured

set -e

BASE_URL="${CAPTCHA_URL:-https://captcha-p.asprin.dev}"
LINKS_URL="${LINKS_URL:-https://links.asprin.dev}"

echo "🔒 Security Headers Test"
echo "========================"
echo ""

test_headers() {
    local URL=$1
    local NAME=$2
    
    echo "Testing: $NAME"
    echo "URL: $URL"
    echo "---"
    
    HEADERS=$(curl -s -I -X GET "$URL" 2>/dev/null)
    
    # Required headers
    REQUIRED_HEADERS=(
        "strict-transport-security"
        "x-content-type-options"
        "x-frame-options"
        "content-security-policy"
        "referrer-policy"
        "x-xss-protection"
    )
    
    PASS=0
    FAIL=0
    
    for header in "${REQUIRED_HEADERS[@]}"; do
        if echo "$HEADERS" | grep -qi "$header"; then
            echo "  ✅ $header: PRESENT"
            VALUE=$(echo "$HEADERS" | grep -i "$header" | head -1 | cut -d: -f2-)
            echo "     Value:$VALUE"
            ((PASS++))
        else
            echo "  ❌ $header: MISSING"
            ((FAIL++))
        fi
    done
    
    # CORS headers (should be present for API)
    echo ""
    echo "CORS Headers:"
    
    CORS_RESPONSE=$(curl -s -I -X OPTIONS "$URL" \
        -H "Origin: https://links.asprin.dev" \
        -H "Access-Control-Request-Method: POST" 2>/dev/null)
    
    if echo "$CORS_RESPONSE" | grep -qi "access-control-allow-origin"; then
        ORIGIN=$(echo "$CORS_RESPONSE" | grep -i "access-control-allow-origin" | cut -d: -f2-)
        echo "  ✅ Access-Control-Allow-Origin:$ORIGIN"
        
        if echo "$ORIGIN" | grep -q "\*"; then
            echo "     ⚠️  WARNING: Wildcard origin (*) is insecure!"
            ((FAIL++))
        else
            ((PASS++))
        fi
    else
        echo "  ❌ Access-Control-Allow-Origin: MISSING"
        ((FAIL++))
    fi
    
    if echo "$CORS_RESPONSE" | grep -qi "access-control-allow-credentials"; then
        echo "  ✅ Access-Control-Allow-Credentials: PRESENT"
        ((PASS++))
    fi
    
    echo ""
    echo "Score: $PASS passed, $FAIL failed"
    echo ""
    echo "=========================================="
    echo ""
}

# Test CAPTCHA server
test_headers "$BASE_URL/api/image/api/init" "CAPTCHA Image Server"

# Test Links server
test_headers "$LINKS_URL" "Links Server"

# Additional checks
echo "Additional Security Checks:"
echo "---"

# Check for server version disclosure
echo -n "Server version disclosure: "
SERVER_HEADER=$(curl -s -I "$BASE_URL/health" 2>/dev/null | grep -i "^server:" | head -1)
if echo "$SERVER_HEADER" | grep -qi "cloudflare"; then
    echo "✅ Using Cloudflare (version hidden)"
elif [ -n "$SERVER_HEADER" ]; then
    echo "⚠️  $SERVER_HEADER"
else
    echo "✅ Not disclosed"
fi

# Check for X-Powered-By
echo -n "X-Powered-By disclosure: "
POWERED_BY=$(curl -s -I "$LINKS_URL" 2>/dev/null | grep -i "x-powered-by" | head -1)
if [ -n "$POWERED_BY" ]; then
    echo "⚠️  $POWERED_BY"
    echo "   Consider removing this header"
else
    echo "✅ Not present"
fi

# Check HTTPS redirect
echo -n "HTTPS enforcement: "
HTTP_RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" "http://${BASE_URL#https://}" 2>/dev/null || echo "error")
if [ "$HTTP_RESPONSE" == "301" ] || [ "$HTTP_RESPONSE" == "308" ]; then
    echo "✅ HTTP redirects to HTTPS"
elif [ "$HTTP_RESPONSE" == "error" ]; then
    echo "✅ HTTP not accessible (good)"
else
    echo "⚠️  HTTP returns $HTTP_RESPONSE"
fi

echo ""
echo "Security Headers Test Complete."
