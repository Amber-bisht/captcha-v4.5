CAPTCHA Security Hardening Verification
Date: 2026-01-22 Status: ✅ Phase 1 Complete, ✅ Phase 2 Mostly Complete (P2.1 Pending)

🔒 Implemented Security Fixes
Phase 1: Critical Hardening
ID	Fix	Implemented In	Verification
P1.1	JWT_SECRET Enforcement	captcha_server, capcha-img	Server now exits if JWT_SECRET is missing. No fallback to insecure random bytes.
P1.2	Token Replay Protection	captcha_server/siteverify	siteverify endpoint checks Redis 
usedNonce
 key. Tokens are one-time use only.
P1.3	Redis Rate Limiting	capcha-img	Replaced in-memory limiter with 
RedisRateLimitStore
. Enables horizontal scaling.
P1.4	Standardized IP Extraction	capcha-img	Created 
ipExtractor.ts
 to handle X-Forwarded-For and X-Real-IP consistently.
P1.5	Case-Sensitive CAPTCHA	Both servers	Text comparison no longer uses .toLowerCase(). A != a.
Phase 2: Structural Improvements
ID	Fix	Implemented In	Verification
P2.1	Client-side Scrypt	⚠️ Skipped	Requires adding scrypt-js dependency to build pipeline.
P2.2	Randomized Expiration	Both servers	Expires in 4-6 minutes (randomized) instead of fixed 5 minutes.
P2.3	Constant-Time Comparison	captcha_server	Using crypto.timingSafeEqual for secret key validation.
P2.4	Comprehensive Monitoring	Both servers	Added 
SecurityLogger
 and 
MetricsService
.
Phase 3: Monitoring & Metrics (Requested)
ID	Feature	Details
M1	Security Logger	Structured JSON logs for auth_failure, token_reuse, rate_limit_exceeded.
M2	Performance Metrics	Tracking solve times, success/fail rates by type (spatial/text).
M3	Fingerprint Entropy	Unique fingerprints per day tracked in Redis to detect farming/spoofing.
📋 Configuration Required
Ensure the following environment variables are set in your production environment:

# Required for P1.1
JWT_SECRET=your-secure-random-secret-key-at-least-32-chars
# Required for P1.3
REDIS_URL=redis://your-redis-host:6379
# Recommended for P1.4
TRUST_PROXY=true  # If behind Nginx/Cloudflare
🔍 Verification Steps
Test Rate Limiting:

Send >10 challenge requests from same IP.
Verify 11th request receives 429 Too Many Requests.
Verify Retry-After header is present.
Test Token Replay:

Solve a CAPTCHA and get a success token.
Call /siteverify with the token -> Should return success: true.
Call /siteverify AGAIN with same token -> Should return success: false and error token-already-used.
Check Logs:

Monitor console output for SECURITY_EVENT logs.
Check Redis keys captcha:metrics:* for accumulated stats.
⚠️ Known Limitations
Client-side Scrypt: High-risk users getting scrypt challenges will fail until scrypt-js is added to the client bundle.
Strict Case Sensitivity: Users might find text CAPTCHAs slightly harder. Ensure font clarity distinguishes O vs 0, l vs 1 (already handled in generator config).