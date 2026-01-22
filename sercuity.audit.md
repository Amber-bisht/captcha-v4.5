CAPTCHA v4 System Security Audit Report
Date: 2026-01-22
Scope: Full-spectrum security audit of CAPTCHA server and public v4 API

Executive Summary
The CAPTCHA system demonstrates mature security architecture with multiple defense layers. However, several vulnerabilities and weaknesses require attention to maximize attacker cost and close bypass paths.

Category	Status
Token Security	🟡 Good, needs hardening
Rate Limiting	🟡 Moderate, can be bypassed
PoW System	🟢 Well-implemented
Image Generation	🔴 SVG-CAPTCHA is ML-vulnerable
Session Binding	🟢 Properly implemented
Device Reputation	🟢 Strong Redis-backed system
Client-side Trust	🟡 Some client-side dependencies
A. Confirmed Vulnerabilities and Weak Points
Critical (Exploit Now)
A1. JWT_SECRET Fallback to Random Bytes
Location: 
tokenService.ts

const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(32).toString('hex');
Issue: If JWT_SECRET is not set, each server restart generates a new secret. In multi-instance deployments, tokens become unpredictable between pods.

CAUTION

The capcha-img server correctly exits on missing JWT_SECRET (line 44-47), but captcha_server does not. This inconsistency is dangerous.

Attack Vector: Attacker could force server restarts to invalidate all active tokens, causing denial of service.

A2. SVG-CAPTCHA is Trivially ML-Solvable
Location: 
captchaGenerator.ts

The captcha_server uses svg-captcha library which generates text-based SVG CAPTCHAs.

Why This is Broken:

OCR models (Tesseract, EasyOCR) achieve 70-90% accuracy on svg-captcha
ML-based solvers (CNN, CRNN) achieve 95%+ with minimal training
No 3D transforms, perspective, or adversarial noise
Limited character set (ignoreChars: '0o1il') reduces entropy significantly
WARNING

The capcha-img server correctly defaults to spatial CAPTCHA for all risk levels (see riskAnalyzer.ts:333). However, captcha_server still serves text CAPTCHAs.

A3. Success Token One-Time Use Not Enforced in captcha_server
Location: 
server.ts

The /api/siteverify endpoint in captcha_server does not check if the success token has already been used:

// Verify the token
const result = TokenService.verifySuccessToken(token, remoteip);
// No call to check/mark token as used!
Attack Vector: A valid success token can be replayed across multiple form submissions until it expires (90s window).

Contrast with capcha-img: Properly uses RedisStore.isTokenUsed() and RedisStore.markTokenUsed().

High Severity
A4. Rate Limiter Uses In-Memory Storage
Location: 
rateLimiter.ts

The rate limiter uses express-rate-limit with default in-memory store, not Redis.

Issue:

Horizontal scaling breaks rate limiting (each instance has separate counters)
Server restarts clear all rate limit state
Attackers can target specific instances
Mitigation: Use rate-limit-redis package with existing Redis connection.

A5. PoW Challenge Store Uses In-Memory Map
Location: 
proofOfWork.ts

const challengeStore = new Map<string, PoWChallenge & { createdAt: number }>();
Issue: Same as rate limiter - doesn't scale horizontally and loses state on restart.

NOTE

The RedisStore.setPoWChallenge() and 
consumePoWChallenge()
 functions exist and are used in the main server flow, but ProofOfWorkSystem.verifySolution() uses the in-memory Map. This appears to be dead code from an older implementation.

A6. IP Address Extraction Inconsistency
Location: Multiple files

Different files extract client IP differently:

File	Method
fingerprint.ts
x-forwarded-for split first, then x-real-ip, then remoteAddress
rateLimiter.ts
req.ip or req.socket.remoteAddress
server.ts
Both patterns used inconsistently
Attack Vector: Attackers can manipulate X-Forwarded-For headers to:

Bypass IP-based rate limits
Pollute fingerprint hashes
Evade device reputation tracking
A7. Timing Attack Vector in Password/Token Comparison
Location: 
tokenService.ts

String comparisons like decoded.challengeId !== 'success' are not constant-time. While JWT signature verification is not vulnerable, any plaintext comparisons could leak information.

Medium Severity
A8. Client-Side PoW Only Supports SHA-256
Location: 
proofOfWork.ts

The client-side solver only implements SHA-256, but the server supports Scrypt for high-risk users.

Issue: High-risk requests configured for scrypt PoW will fail client-side.

A9. Fingerprint Includes Spoofable Headers
Location: 
fingerprint.ts

While the code warns about spoofable headers, the 
generateServerFingerprint()
 function still includes potentially spoofable elements like x-tls-version and x-tls-cipher which depend on reverse proxy configuration.

A10. Challenge Expiration Time is Static
Location: Various

All challenges expire in exactly 5 minutes (300000ms). This predictability allows attackers to:

Pre-farm PoW solutions just before requesting challenges
Time token harvesting exactly
Low Severity
A11. Verbose Error Messages
Location: Multiple

Errors like "Session validation failed", "Challenge not found or expired" help attackers understand system state.

A12. Metrics Endpoint Publicly Accessible
Location: 
server.ts

/api/metrics endpoint exposes internal statistics without authentication.

B. Phase-Wise Hardening Roadmap
Phase 1: Immediate Fixes (1-3 days, High Impact)
Fix	Threat Mitigated	Current Vulnerability	How It Raises Attacker Cost
P1.1 Add JWT_SECRET requirement to captcha_server	Token forgery in multi-pod	Random secret per restart	Tokens work consistently, can't exploit restart
P1.2 Add token replay protection to captcha_server/siteverify	Token replay attacks	No one-time-use check	Each token valid for single use only
P1.3 Use Redis store for rate limiter	Distributed rate limit bypass	In-memory per-instance	Consistent limits across all pods
P1.4 Standardize IP extraction to single utility	IP spoofing for bypass	Inconsistent extraction	Single source of truth for client IP
Implementation Steps:

// captcha_server/src/utils/tokenService.ts
- const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(32).toString('hex');
+ const JWT_SECRET = process.env.JWT_SECRET;
+ if (!JWT_SECRET) {
+   console.error('[FATAL] JWT_SECRET environment variable is required');
+   process.exit(1);
+ }
Phase 2: Structural Improvements (1-2 weeks, Moderate Effort)
Fix	Threat Mitigated	Current Vulnerability	How It Raises Attacker Cost
P2.1 Deprecate text CAPTCHA, use spatial only	ML-based solving	svg-captcha is ML-vulnerable	Requires custom ML model, harder to train
P2.2 Add scrypt solver to client-side	PoW difficulty bypass	Only SHA-256 implemented	GPU farming becomes prohibitively expensive
P2.3 Randomize challenge expiration (4-6 min)	Timing-based farming	Fixed 5-min window	Can't pre-compute or time attacks precisely
P2.4 Add constant-time comparison for tokens	Timing attacks	Direct string comparison	Eliminates timing side-channel
P2.5 Require trusted proxy configuration	IP spoofing	Trust all forwarded headers	Only accept IP from configured proxies
For P2.2 - Client-side Scrypt Implementation:

Use scrypt-js library (pure JS, no WASM needed):

import { scrypt } from 'scrypt-js';
async function solveScryptPoW(challenge) {
  const N = challenge.scryptParams.N;
  const r = challenge.scryptParams.r;
  const p = challenge.scryptParams.p;
  const salt = Buffer.from(challenge.nonce, 'hex');
  
  let counter = 0;
  while (true) {
    const solution = counter.toString();
    const key = await scrypt(
      Buffer.from(solution),
      salt,
      N, r, p, 32
    );
    const hash = Buffer.from(key).toString('hex');
    if (hash.startsWith('0'.repeat(challenge.difficulty))) {
      return { solution, hash };
    }
    counter++;
  }
}
Phase 3: Advanced Defenses (2-4 weeks, High Effort)
Fix	Threat Mitigated	Current Vulnerability	How It Raises Attacker Cost
P3.1 JA3/JA4 TLS fingerprinting	Headless browser/tooling	Only UA-based detection	Must perfectly emulate real browser TLS stack
P3.2 CAPTCHA farm detection via ML	Human solver farms	No behavioral baseline	Requires training custom models on farm behavior
P3.3 WebGL/Canvas fingerprint binding	Token harvesting	Fingerprint not bound to challenge	Each solve requires same browser context
P3.4 Device attestation (Android SafetyNet/iOS DeviceCheck)	Emulator/rooted device abuse	No native app verification	Requires real, unmodified device
P3.5 Request signing with timestamp	Request tampering	No request integrity	All requests cryptographically bound
C. Limitations That Cannot Be Fully Solved
C1. Human CAPTCHA Farms
Problem: Services like 2Captcha, Anti-Captcha employ real humans to solve CAPTCHAs.

Compensating Controls:

Increase solve count per session (3-5 consecutive solves)
Add time-based puzzles that require waiting (10-15s minimum)
Implement behavioral biometrics during solve
Monitor for unusual traffic patterns (bursts from certain regions)
Economic barrier: PoW cost + multiple rounds makes farming uneconomical
C2. Residential Proxy Networks
Problem: Services like Bright Data, NetNut provide millions of residential IPs.

Compensating Controls:

Focus on device fingerprinting, not IP reputation
ASN diversity detection (same fingerprint across many ASNs = suspicious)
Geographic velocity checks (impossible travel detection)
Session binding to fingerprint, not IP
C3. AI Model Training on Your CAPTCHAs
Problem: Attackers can collect CAPTCHAs and train custom models.

Compensating Controls:

Rotate visual themes/styles frequently
Add adversarial perturbations to images
Use spatial CAPTCHAs requiring 3D understanding
Implement "impossible" CAPTCHAs occasionally as honeypots
D. Monitoring and Anomaly Detection
Key Signals Indicating Active Bypass Attempts
Signal	Detection Query	Response
Solve time < 1.5s	solveTime < 1500ms	Auto-fail, increase device suspicion
High PoW hash rate	hashRate > 2M/s	Likely GPU farm, require scrypt
Fingerprint collision	Same hash, different IPs	Token harvesting attempt
Session skip patterns	/verify without prior /init	Block, ban device
Geographic impossibility	> 500km in < 1 hour	Require additional verification
Retry spike	> 5 failures / minute / fingerprint	Temporary ban
Recommended Logging Additions
Add structured logging for security events:

interface SecurityEvent {
  timestamp: string;
  eventType: 'challenge_solve' | 'bypass_attempt' | 'rate_limit' | 'ban';
  fingerprint: string;
  ip: string;
  solveTime?: number;
  riskScore: number;
  outcome: 'success' | 'failure' | 'blocked';
  details: Record<string, any>;
}
Dashboard Metrics to Track
Solve Success Rate by Risk Level - Low risk should be 85%+, if >95% for high risk, detection is failing
Average Solve Time Distribution - Bimodal (bots vs humans) indicates bypass attempts
PoW Hash Rate Distribution - Spike above 1M/s indicates GPU farms
Fingerprint Entropy - Decreasing unique fingerprints per day indicates fingerprint spoofing
Token Replay Attempts - Should be 0; any non-zero indicates vulnerability
E. Summary of Recommendations by Priority
Must Fix Immediately (Before Production)
✅ Enforce JWT_SECRET in captcha_server
✅ Add token replay protection to captcha_server/siteverify
✅ Use Redis-backed rate limiting
Should Fix This Sprint
🔶 Deprecate text CAPTCHA endpoint, use spatial only
🔶 Implement client-side scrypt solver
🔶 Standardize IP extraction utility
Plan for Next Quarter
📋 JA3/JA4 TLS fingerprinting
📋 Behavioral biometrics during solve
📋 Geographic velocity checks
Appendix: Existing Security Test Coverage
The 
security_scanner.js
 covers:

✅ Endpoint availability
✅ Security headers
✅ CORS configuration
✅ PoW nonce reuse
✅ Rate limiting
✅ Honeypot detection
✅ Bot UA blocking
✅ Input validation
Missing test coverage:

❌ Success token replay
❌ Cross-instance rate limit bypass
❌ Fingerprint manipulation
❌ Scrypt PoW verification
❌ Timing attack detection