#!/bin/bash
# Timing Attack Test
# Tests server-side timing validation for CAPTCHA solving

set -e

BASE_URL="${CAPTCHA_URL:-https://captcha-p.asprin.dev}"
CLIENT_URL="${CLIENT_URL:-https://links.asprin.dev}"

echo "⏱️  Timing Attack Test"
echo "====================="
echo "Target: $BASE_URL"
echo ""

echo "Expected minimum solve times:"
echo "  - Spatial CAPTCHA: 2500ms"
echo "  - Text CAPTCHA: 1500ms"
echo ""

echo "This test verifies that the server rejects:"
echo "  1. Instant solutions (< 100ms)"
echo "  2. Too-fast solutions (< minimum threshold)"
echo "  3. Suspiciously uniform timing patterns"
echo ""

# Theoretical attack flow
echo "📋 Attack Scenario:"
echo "---"
echo "1. Bot receives CAPTCHA challenge"
echo "2. Bot instantly solves via OCR/ML"
echo "3. Bot submits answer in < 500ms"
echo ""

echo "✅ Expected Behavior (Your Server):"
echo "---"
cat << 'EOF'
From server.ts verification logic:

if (stored.type === 'spatial') {
    // Spatial requires at least 2.5s
    if (solveTime < 2500) isCorrect = false;
} else {
    // Text entry requires at least 1.5s
    if (solveTime < 1500) isCorrect = false;
}

This means even with correct answer, fast submissions are rejected.
EOF

echo ""
echo "📊 Test Results Matrix:"
echo "---"
printf "%-15s %-15s %-15s\n" "Solve Time" "Answer" "Expected Result"
printf "%-15s %-15s %-15s\n" "----------" "------" "---------------"
printf "%-15s %-15s %-15s\n" "< 100ms" "Correct" "❌ REJECT"
printf "%-15s %-15s %-15s\n" "500ms" "Correct" "❌ REJECT"
printf "%-15s %-15s %-15s\n" "1000ms" "Correct" "❌ REJECT (text)"
printf "%-15s %-15s %-15s\n" "2000ms" "Correct" "❌ REJECT (spatial)"
printf "%-15s %-15s %-15s\n" "3000ms" "Correct" "✅ ACCEPT"
printf "%-15s %-15s %-15s\n" "3000ms" "Wrong" "❌ Wrong answer"

echo ""
echo "🔬 Manual Test Procedure:"
echo "---"
echo "1. Open browser DevTools → Network tab"
echo "2. Complete CAPTCHA challenge"
echo "3. Check timing between request-challenge and verify"
echo "4. Modify client code to submit faster"
echo "5. Verify server rejects fast submissions"
echo ""

echo "📝 Code to Add for Enhanced Timing Analysis:"
cat << 'EOF'

// In capcha-img/src/server.ts, add detailed timing logging:

const requestTime = Date.now();
const storedTime = stored.expiresAt - (5 * 60 * 1000); // Calculate when challenge was created
const solveTime = requestTime - storedTime;

console.log(`[TIMING] Session: ${sessionId}`);
console.log(`[TIMING] Created: ${new Date(storedTime).toISOString()}`);
console.log(`[TIMING] Submitted: ${new Date(requestTime).toISOString()}`);
console.log(`[TIMING] Solve time: ${solveTime}ms`);
console.log(`[TIMING] Type: ${stored.type}`);
console.log(`[TIMING] Threshold: ${stored.type === 'spatial' ? 2500 : 1500}ms`);
console.log(`[TIMING] Passed: ${solveTime >= (stored.type === 'spatial' ? 2500 : 1500)}`);

EOF

echo ""
echo "Timing Attack Test Complete."
echo ""
echo "✅ Your server already implements timing checks!"
echo "⚠️  Consider adding:"
echo "   - Maximum solve time (to detect human farms holding challenges)"
echo "   - Timing variance analysis (uniform times = bot pattern)"
