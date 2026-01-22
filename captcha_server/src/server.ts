//lets go
import express, { Request, Response } from 'express';
import path from 'path';
import helmet from 'helmet';
import cookieParser from 'cookie-parser';
import { createSessionMiddleware } from './config/session';
import { fingerprintMiddleware } from './middleware/fingerprint';
import {
  challengeRateLimiter,
  verificationRateLimiter,
} from './middleware/rateLimiter';
import {
  csrfTokenMiddleware,
  csrfVerificationMiddleware,
} from './middleware/csrf';
import { TokenService } from './utils/tokenService';
import { CaptchaGenerator } from './utils/captchaGenerator';
import { BehaviorAnalyzer } from './utils/behaviorAnalyzer';
import { challengeStore } from './utils/challengeStore';
// Phase A Security Enhancements
import { sessionManager } from './security/sessionManager';
import { deviceReputation } from './security/deviceReputation';
// SECURITY FIX P1.2: Import Redis for token replay prevention
import { setWithTTL, exists, KEYS } from './config/redis';
// SECURITY MONITORING: Import Logger and Metrics
import { SecurityLogger } from './utils/securityLogger';
import { MetricsService } from './utils/metricsService';

import cors from 'cors';

const app = express();
const PORT = process.env.PORT || 3000;

// Allowed origins for CORS
const ALLOWED_ORIGINS = [
  'https://links.asprin.dev',
  'https://www.links.asprin.dev',
  // Development
  'http://localhost:3000',
  'http://localhost:3001',
];

// Security headers
app.use(helmet({
  crossOriginEmbedderPolicy: false,
  crossOriginResourcePolicy: { policy: "cross-origin" },
}));

// CORS - Strict origin whitelist
app.use(cors({
  origin: (origin, callback) => {
    // SECURITY FIX H4: Reject requests with no origin to prevent script-based attacks
    if (!origin) {
      console.warn('[CORS] Blocked request with no origin');
      return callback(new Error('Origin required'), false);
    }

    if (ALLOWED_ORIGINS.includes(origin)) {
      return callback(null, true);
    }

    console.warn(`CORS blocked origin: ${origin}`);
    return callback(new Error('Not allowed by CORS'), false);
  },
  credentials: true,
  methods: ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'X-CSRF-Token', 'X-Captcha-Site-Key', 'Authorization'],
}));

// Middleware
app.use(express.static(path.join(__dirname, '../public')));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// Session configuration
app.use(createSessionMiddleware());

// Fingerprint middleware (must be before routes)
app.use(fingerprintMiddleware);

// CSRF protection is disabled for cross-domain compatibility.
// Security is maintained via JWT tokens, fingerprinting, and IP verification.

// challengeStore is now Redis-backed (imported from ./utils/challengeStore)

// Route to get captcha challenge
app.get('/captcha', challengeRateLimiter, async (req: Request, res: Response) => {
  try {
    // Get fingerprint and IP early for velocity check
    const fingerprint = req.fingerprint?.hash || 'unknown';
    const ip = req.fingerprint?.components.ip || 'unknown';

    // Phase A: Velocity check before processing
    const velocityCheck = await deviceReputation.recordRequest(fingerprint);
    if (!velocityCheck.allowed) {
      console.warn(`[SECURITY] Velocity limit exceeded for ${fingerprint.substring(0, 8)}: ${velocityCheck.velocityScore} req/min`);
      return res.status(429).json({
        success: false,
        message: 'Too many requests. Please wait before trying again.',
        retryAfter: 60,
      });
    }

    // Check for headless browser
    const userAgent = req.headers['user-agent'] || '';
    const isHeadless = BehaviorAnalyzer.detectHeadlessBrowser(
      userAgent,
      req.headers as Record<string, string>
    );

    if (isHeadless) {
      await deviceReputation.recordSuspiciousActivity(fingerprint, {
        type: 'headless_browser',
        details: `User-Agent: ${userAgent.substring(0, 50)}`,
        severity: 'high',
      });
      return res.status(403).json({
        success: false,
        message: 'Automated requests are not allowed',
      });
    }

    // Phase A: Create session for stage binding
    const session = await sessionManager.createSession(fingerprint, ip);

    // Generate challenge
    const challenge = CaptchaGenerator.generateChallenge();
    if (!challenge) {
      return res.status(500).json({
        success: false,
        message: 'Failed to generate challenge',
      });
    }

    // Associate challenge with session
    await sessionManager.associateChallenge(session.sessionId, challenge.id);

    // Generate token (async for Redis nonce storage)
    const tokenResponse = await TokenService.generateToken(
      challenge.id,
      fingerprint,
      ip
    );

    // Store challenge (Redis handles TTL automatically)
    await challengeStore.set(challenge.id, {
      challenge,
      fingerprint,
      ip,
      createdAt: Date.now(),
    });

    // Store challenge ID and token in response headers
    res.setHeader('X-Challenge-Id', challenge.id);
    res.setHeader('X-Token', tokenResponse.token);
    res.setHeader('X-CSRF-Token', req.csrfToken || '');
    res.setHeader('X-Expires-In', tokenResponse.expiresIn.toString());
    // Phase A: Include session ID for stage binding
    res.setHeader('X-Session-Id', session.sessionId);

    // Return SVG image directly (for compatibility with existing client)
    res.type('svg');
    res.status(200).send(challenge.image);
  } catch (error) {
    console.error('Error generating captcha:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error',
    });
  }
});

// Route to verify captcha
app.post(
  '/verify',
  verificationRateLimiter,
  async (req: Request, res: Response) => {
    try {
      const { captcha, token, challengeId, behaviorData, sessionId } = req.body;

      // Validate input - SECURITY FIX H1: sessionId is now mandatory
      if (!captcha || !token || !challengeId || !sessionId) {
        return res.json({
          success: false,
          message: 'Missing required fields (captcha, token, challengeId, sessionId)',
        });
      }

      // Get fingerprint and IP
      const fingerprint = req.fingerprint?.hash || 'unknown';
      const ip = req.fingerprint?.components.ip || 'unknown';

      // Phase A: Velocity check
      const velocityCheck = await deviceReputation.checkVelocity(fingerprint);
      if (!velocityCheck.allowed) {
        return res.status(429).json({
          success: false,
          message: 'Rate limit exceeded',
          retryAfter: Math.ceil((velocityCheck.recommendedDelay || 1000) / 1000),
        });
      }

      // Phase A: Session validation - MANDATORY (H1 fix)
      const sessionValidation = await sessionManager.validateTransition(
        sessionId,
        fingerprint,
        ip,
        'init', // Expected to be at init stage (challenge was issued at init)
        'verified'
      );

      if (!sessionValidation.valid) {
        console.warn(`[SECURITY] Session validation failed: ${sessionValidation.error}`);
        await deviceReputation.recordSuspiciousActivity(fingerprint, {
          type: 'session_violation',
          details: sessionValidation.error || 'Unknown session error',
          severity: 'high',
        });
        return res.json({
          success: false,
          message: 'Session validation failed',
        });
      }

      // Verify challenge belongs to this session
      if (!(await sessionManager.verifyChallengeId(sessionId, challengeId))) {
        console.warn(`[SECURITY] Challenge-session mismatch for ${fingerprint.substring(0, 8)}`);
        await deviceReputation.recordSuspiciousActivity(fingerprint, {
          type: 'challenge_session_mismatch',
          details: `Challenge ${challengeId.substring(0, 8)} not associated with session`,
          severity: 'high',
        });
        return res.json({
          success: false,
          message: 'Invalid challenge for this session',
        });
      }

      // Verify token (async for Redis nonce check)
      const tokenVerification = await TokenService.verifyToken(
        token,
        fingerprint,
        ip
      );

      if (!tokenVerification.valid) {
        await deviceReputation.recordChallengeAttempt(fingerprint, false, ip, {
          type: 'token_verification_failed',
          details: tokenVerification.error || 'Unknown token error',
          severity: 'medium',
        });
        return res.json({
          success: false,
          message: tokenVerification.error || 'Token verification failed',
        });
      }

      // Get challenge from store
      const stored = await challengeStore.get(challengeId);
      if (!stored) {
        return res.json({
          success: false,
          message: 'Challenge not found or expired',
        });
      }

      // Check if challenge is expired
      if (CaptchaGenerator.isExpired(stored.challenge!)) {
        await challengeStore.delete(challengeId);
        return res.json({
          success: false,
          message: 'Challenge expired',
        });
      }

      // Verify fingerprint and IP match
      if (
        stored.fingerprint !== fingerprint ||
        stored.ip !== ip
      ) {
        await deviceReputation.recordSuspiciousActivity(fingerprint, {
          type: 'fingerprint_ip_mismatch',
          details: `Stored: ${stored.fingerprint.substring(0, 8)}/${stored.ip}, Got: ${fingerprint.substring(0, 8)}/${ip}`,
          severity: 'high',
        });
        return res.json({
          success: false,
          message: 'Request origin mismatch',
        });
      }

      // Analyze behavior if provided
      if (behaviorData) {
        const behaviorScore = BehaviorAnalyzer.analyzeBehavior(behaviorData);
        if (behaviorScore.riskLevel === 'high') {
          await challengeStore.delete(challengeId);
          await deviceReputation.recordChallengeAttempt(fingerprint, false, ip, {
            type: 'suspicious_behavior',
            details: `Risk score: ${behaviorScore.score}`,
            severity: 'high',
          });
          return res.json({
            success: false,
            message: 'Suspicious behavior detected',
          });
        }
      }

      if (
        captcha === stored.challenge!.text
      ) {
        // Clear challenge to prevent reuse
        await challengeStore.delete(challengeId);

        // Phase A: Invalidate session after successful verification
        if (sessionId) {
          await sessionManager.invalidateSession(sessionId);
        }

        // Record successful challenge
        await deviceReputation.recordChallengeAttempt(fingerprint, true, ip);

        // Generate success token
        const successToken = TokenService.generateSuccessToken(
          fingerprint,
          ip
        );

        return res.json({
          success: true,
          message: 'Captcha verified successfully!',
          token: successToken.token,
        });
      } else {
        // Record failed challenge
        await deviceReputation.recordChallengeAttempt(fingerprint, false, ip, {
          type: 'wrong_answer',
          details: 'Incorrect captcha answer',
          severity: 'low',
        });
        return res.json({
          success: false,
          message: 'Incorrect captcha. Please try again.',
        });
      }
    } catch (error) {
      console.error('Error verifying captcha:', error);
      res.status(500).json({
        success: false,
        message: 'Internal server error',
      });
    }
  }
);

// ============================================
// SITEVERIFY ENDPOINT (for server-to-server validation)
// Compatible with Cloudflare Turnstile / Google reCAPTCHA API format
// ============================================
app.post('/api/siteverify', async (req: Request, res: Response) => {
  try {
    const { secret, response: token, remoteip } = req.body;

    // Validate required fields
    if (!secret || !token) {
      return res.status(400).json({
        success: false,
        'error-codes': ['missing-input-secret', 'missing-input-response'].filter(
          (_, i) => (i === 0 && !secret) || (i === 1 && !token)
        ),
      });
    }

    // Verify secret key
    const expectedSecret = process.env.CAPTCHA_SECRET_KEY;
    if (!expectedSecret) {
      console.error('[SITEVERIFY] CAPTCHA_SECRET_KEY not configured');
      return res.status(500).json({
        success: false,
        'error-codes': ['internal-error'],
      });
    }

    // SECURITY FIX P2.3: Use constant-time comparison to prevent timing attacks
    const crypto = require('crypto');
    const secretBuffer = Buffer.from(secret);
    const expectedBuffer = Buffer.from(expectedSecret);

    const isValidSecret = secretBuffer.length === expectedBuffer.length &&
      crypto.timingSafeEqual(secretBuffer, expectedBuffer);

    if (!isValidSecret) {
      SecurityLogger.warn('Invalid secret key attempt', { ip: remoteip || req.ip });
      return res.json({
        success: false,
        'error-codes': ['invalid-input-secret'],
      });
    }

    // SECURITY FIX P1.2: Check if token has already been used (replay attack prevention)
    const tokenHash = require('crypto').createHash('sha256').update(token).digest('hex');
    const usedTokenKey = KEYS.usedNonce(`siteverify:${tokenHash}`);
    const isTokenUsed = await exists(usedTokenKey);

    if (isTokenUsed) {
      SecurityLogger.warn('Token replay attempt detected', { token: tokenHash.substring(0, 8), ip: remoteip });
      await MetricsService.recordSecurityEvent('replay');
      return res.json({
        success: false,
        'error-codes': ['token-already-used'],
      });
    }

    // Verify the token
    const result = TokenService.verifySuccessToken(token, remoteip);

    if (!result.valid) {
      SecurityLogger.info('Token verification failed', { error: result.error, ip: remoteip });
      await MetricsService.recordVerification(false);
      return res.json({
        success: false,
        'error-codes': [result.error || 'invalid-input-response'],
      });
    }

    // SECURITY FIX P1.2: Mark token as used (TTL = 10 minutes to match token expiry)
    await setWithTTL(usedTokenKey, '1', 600);

    // SECURITY MONITORING: Record success metric and fingerprint entropy
    await MetricsService.recordVerification(true, undefined, result.fingerprint);
    SecurityLogger.info('Token verified successfully', { fingerprint: result.fingerprint, ip: result.ip });

    // Success response (matches Cloudflare/Google format)
    return res.json({
      success: true,
      challenge_ts: result.challengeTs,
      hostname: 'captcha-p.asprin.dev',
      // Additional custom fields
      fingerprint: result.fingerprint,
      ip: result.ip,
    });
  } catch (error) {
    console.error('[SITEVERIFY] Error:', error);
    return res.status(500).json({
      success: false,
      'error-codes': ['internal-error'],
    });
  }
});

// Health check endpoint
app.get('/health', (req: Request, res: Response) => {
  res.status(200).json({
    status: 'healthy',
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    service: 'captcha-server',
  });
});

app.listen(PORT, () => {
  console.log(`Server is running at http://localhost:${PORT}`);
});
