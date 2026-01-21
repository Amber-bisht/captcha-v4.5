#!/bin/bash
# Proof of Work Difficulty Test
# Tests the strength of the PoW challenge

set -e

BASE_URL="${CAPTCHA_URL:-https://captcha-p.asprin.dev}"
CLIENT_URL="${CLIENT_URL:-https://links.asprin.dev}"

echo "⛏️  Proof of Work Difficulty Test"
echo "================================="
echo "Target: $BASE_URL"
echo ""

# Get multiple PoW challenges to analyze
echo "Collecting PoW challenge samples..."
echo ""

SAMPLES=5
DIFFICULTIES=()

for i in $(seq 1 $SAMPLES); do
    RESPONSE=$(curl -s "$BASE_URL/api/image/api/init" \
        -H "Origin: $CLIENT_URL" \
        -H "User-Agent: Mozilla/5.0")
    
    DIFFICULTY=$(echo "$RESPONSE" | jq -r '.difficulty // 0')
    NONCE=$(echo "$RESPONSE" | jq -r '.nonce')
    
    echo "Sample $i: Difficulty=$DIFFICULTY, Nonce=${NONCE:0:16}..."
    DIFFICULTIES+=($DIFFICULTY)
    
    # Small delay between requests
    sleep 0.5
done

echo ""
echo "📊 Analysis:"
echo "---"

# Calculate averages
SUM=0
MIN=999
MAX=0
for d in "${DIFFICULTIES[@]}"; do
    SUM=$((SUM + d))
    if [ $d -lt $MIN ]; then MIN=$d; fi
    if [ $d -gt $MAX ]; then MAX=$d; fi
done
AVG=$((SUM / SAMPLES))

echo "Samples collected: $SAMPLES"
echo "Min difficulty: $MIN"
echo "Max difficulty: $MAX"  
echo "Average difficulty: $AVG"
echo ""

# Difficulty analysis
echo "⏱️  Iteration Estimates:"
echo "---"
echo "Difficulty 4 → ~65,536 iterations (~130ms)"
echo "Difficulty 5 → ~1,048,576 iterations (~2s)"
echo "Difficulty 6 → ~16,777,216 iterations (~33s)"
echo "Difficulty 7 → ~268,435,456 iterations (~9min)"
echo ""

if [ $AVG -lt 4 ]; then
    echo "❌ WARNING: Difficulty too low!"
    echo "   Bots can solve this in <100ms"
    echo "   Recommendation: Increase POW_BASE_DIFFICULTY to 4+"
elif [ $AVG -eq 4 ]; then
    echo "⚠️  CAUTION: Default difficulty"
    echo "   Provides basic protection (~130ms)"
    echo "   Consider increasing for high-risk users"
elif [ $AVG -eq 5 ]; then
    echo "✅ GOOD: Moderate difficulty"
    echo "   Adds ~2s computational cost"
    echo "   Good balance for normal traffic"
elif [ $AVG -ge 6 ]; then
    echo "✅ EXCELLENT: High difficulty"
    echo "   Adds significant computational cost"
    echo "   May impact user experience on slow devices"
fi

echo ""
echo "📝 Security Considerations:"
echo "---"
echo "1. PoW difficulty should scale with risk score"
echo "2. VPN/Datacenter IPs should get higher difficulty"
echo "3. Repeat offenders should get progressively harder PoW"
echo "4. Monitor solve times to detect bot farms with GPUs"
echo ""

echo "🔧 Recommended Configuration:"
cat << 'EOF'

# In utils/proofOfWork.ts:
const RISK_DIFFICULTY_MAP = {
    'low': 4,      // Normal users: ~130ms
    'medium': 5,   // Suspicious: ~2s
    'high': 6,     // High risk: ~33s
    'critical': 7  // Known bad: ~9min (practically blocking)
};

# Adaptive difficulty based on:
# - IP reputation score
# - Device reputation score
# - Time of day (attacks often at night)
# - Request velocity

EOF

echo ""
echo "PoW Difficulty Test Complete."
