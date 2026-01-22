import express, { Request, Response, NextFunction } from 'express';
import path from 'path';
import helmet from 'helmet';
import cookieParser from 'cookie-parser';
import crypto from 'crypto';
import cors from 'cors';

import { createSessionMiddleware } from './config/session';
import { fingerprintMiddleware } from './middleware/fingerprint';
import {
  challengeRateLimiter,
  verificationRateLimiter,
  rateLimitManager
} from './middleware/rateLimiter';

import { TokenService } from './utils/tokenService';
import { CaptchaGenerator } from './utils/captchaGenerator';
import { BehaviorAnalyzer } from './utils/behaviorAnalyzer';
import { challengeStore } from './utils/challengeStore';
// Phase A Security Enhancements
import { sessionManager } from './security/sessionManager';
import { deviceReputation } from './security/deviceReputation';
// REDIS
import { setWithTTL, exists, KEYS } from './config/redis';
// SECURITY MONITORING
import { SecurityLogger } from './utils/securityLogger';
import { MetricsService } from './utils/metricsService';
// MONGO & ADMIN
import { connectMongo } from './config/mongo';
import RateLimitConfigModel from './models/RateLimitConfig';
import AdminKeyModel from './models/AdminKey';

const app = express();
const PORT = process.env.PORT || 3000;

// Allowed origins
const ALLOWED_ORIGINS = [
  'https://links.asprin.dev',
  'https://www.links.asprin.dev',
  'http://localhost:3000',
  'http://localhost:3001',
];

app.use(helmet({
  crossOriginEmbedderPolicy: false,
  crossOriginResourcePolicy: { policy: "cross-origin" },
}));

app.use(cors({
  origin: (origin, callback) => {
    if (!origin) return callback(null, true);
    if (ALLOWED_ORIGINS.includes(origin)) return callback(null, true);
    console.warn(`CORS blocked origin: ${origin}`);
    return callback(new Error('Not allowed by CORS'), false);
  },
  credentials: true,
  methods: ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'X-CSRF-Token', 'X-Captcha-Site-Key', 'Authorization', 'x-admin-key'],
}));

app.use(express.static(path.join(__dirname, '../public')));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(createSessionMiddleware());
app.use(fingerprintMiddleware);

// =====================================================
// ADMIN MIDDLEWARE
// =====================================================
const verifyAdminKey = async (req: Request, res: Response, next: NextFunction) => {
  const apiKey = req.headers['x-admin-key'] as string;
  if (!apiKey) return res.status(401).json({ error: 'Missing admin key' });

  const hashed = crypto.createHash('sha256').update(apiKey).digest('hex');
  const validKey = await AdminKeyModel.findOne({ keyHash: hashed });

  if (!validKey) {
    SecurityLogger.warn('Invalid Admin Access Attempt', { ip: req.ip });
    return res.status(403).json({ error: 'Invalid admin key' });
  }

  next();
};

// =====================================================
// ROUTES
// =====================================================

// Route to get captcha challenge
app.get('/captcha', challengeRateLimiter, async (req: Request, res: Response) => {
  try {
    const fingerprint = req.fingerprint?.hash || 'unknown';
    const ip = req.fingerprint?.components.ip || 'unknown';

    const velocityCheck = await deviceReputation.recordRequest(fingerprint);
    if (!velocityCheck.allowed) {
      return res.status(429).json({
        success: false,
        message: 'Too many requests.',
        retryAfter: 60,
      });
    }

    const userAgent = req.headers['user-agent'] || '';
    const isHeadless = BehaviorAnalyzer.detectHeadlessBrowser(
      userAgent,
      req.headers as Record<string, string>
    );

    if (isHeadless) {
      await deviceReputation.recordSuspiciousActivity(fingerprint, { type: 'headless_browser', details: userAgent, severity: 'high' });
      return res.status(403).json({ success: false, message: 'Automated requests not allowed' });
    }

    const session = await sessionManager.createSession(fingerprint, ip);
    const challenge = CaptchaGenerator.generateChallenge();
    if (!challenge) return res.status(500).json({ success: false, message: 'Failed to generate challenge' });

    await sessionManager.associateChallenge(session.sessionId, challenge.id);
    const tokenResponse = await TokenService.generateToken(challenge.id, fingerprint, ip);

    await challengeStore.set(challenge.id, {
      challenge,
      fingerprint,
      ip,
      createdAt: Date.now(),
    });

    res.setHeader('X-Challenge-Id', challenge.id);
    res.setHeader('X-Token', tokenResponse.token);
    // res.setHeader('X-CSRF-Token', req.csrfToken || ''); // CSRF not used
    res.setHeader('X-Expires-In', tokenResponse.expiresIn.toString());
    res.setHeader('X-Session-Id', session.sessionId);

    res.type('svg');
    res.status(200).send(challenge.image);
  } catch (error) {
    console.error('Error generating captcha:', error);
    res.status(500).json({ success: false, message: 'Internal server error' });
  }
});

// Route to verify captcha
app.post('/verify', verificationRateLimiter, async (req: Request, res: Response) => {
  try {
    const { captcha, token, challengeId, behaviorData, sessionId } = req.body;

    if (!captcha || !token || !challengeId || !sessionId) {
      return res.json({ success: false, message: 'Missing required fields' });
    }

    const fingerprint = req.fingerprint?.hash || 'unknown';
    const ip = req.fingerprint?.components.ip || 'unknown';

    const velocityCheck = await deviceReputation.checkVelocity(fingerprint);
    if (!velocityCheck.allowed) {
      return res.status(429).json({ success: false, message: 'Rate limit exceeded', retryAfter: 60 });
    }

    const sessionValidation = await sessionManager.validateTransition(sessionId, fingerprint, ip, 'init', 'verified');

    if (!sessionValidation.valid) {
      await deviceReputation.recordSuspiciousActivity(fingerprint, { type: 'session_violation', details: sessionValidation.error || 'Unknown error', severity: 'high' });
      return res.json({ success: false, message: 'Session validation failed' });
    }

    if (!(await sessionManager.verifyChallengeId(sessionId, challengeId))) {
      return res.json({ success: false, message: 'Invalid challenge for this session' });
    }

    const tokenVerification = await TokenService.verifyToken(token, fingerprint, ip);
    if (!tokenVerification.valid) {
      return res.json({ success: false, message: tokenVerification.error });
    }

    const stored = await challengeStore.get(challengeId);
    if (!stored) return res.json({ success: false, message: 'Challenge not found or expired' });

    if (CaptchaGenerator.isExpired(stored.challenge!)) {
      await challengeStore.delete(challengeId);
      return res.json({ success: false, message: 'Challenge expired' });
    }

    if (stored.fingerprint !== fingerprint || stored.ip !== ip) {
      return res.json({ success: false, message: 'Request origin mismatch' });
    }

    if (behaviorData) {
      const behaviorScore = BehaviorAnalyzer.analyzeBehavior(behaviorData);
      if (behaviorScore.riskLevel === 'high') {
        await challengeStore.delete(challengeId);
        return res.json({ success: false, message: 'Suspicious behavior detected' });
      }
    }

    if (captcha.toLowerCase() === stored.challenge!.text.toLowerCase()) {
      await challengeStore.delete(challengeId);
      if (sessionId) await sessionManager.invalidateSession(sessionId);
      await deviceReputation.recordChallengeAttempt(fingerprint, true, ip);
      const successToken = TokenService.generateSuccessToken(fingerprint, ip);
      return res.json({ success: true, message: 'Verified successfully!', token: successToken.token });
    } else {
      await deviceReputation.recordChallengeAttempt(fingerprint, false, ip, { type: 'wrong_answer', details: 'Incorrect captcha', severity: 'low' });
      return res.json({ success: false, message: 'Incorrect captcha.' });
    }
  } catch (error) {
    console.error('Error verifying captcha:', error);
    res.status(500).json({ success: false, message: 'Internal server error' });
  }
}
);

// SITEVERIFY
app.post('/api/siteverify', async (req: Request, res: Response) => {
  try {
    const { secret, response: token, remoteip } = req.body;
    if (!secret || !token) return res.status(400).json({ success: false, 'error-codes': ['missing-input'] });

    const expectedSecret = process.env.CAPTCHA_SECRET_KEY;
    if (!expectedSecret) return res.status(500).json({ success: false, 'error-codes': ['internal-error'] });

    const secretBuffer = Buffer.from(secret);
    const expectedBuffer = Buffer.from(expectedSecret);
    const isValidSecret = secretBuffer.length === expectedBuffer.length && crypto.timingSafeEqual(secretBuffer, expectedBuffer);

    if (!isValidSecret) return res.json({ success: false, 'error-codes': ['invalid-input-secret'] });

    const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
    const usedTokenKey = KEYS.usedNonce(`siteverify:${tokenHash}`);
    if (await exists(usedTokenKey)) return res.json({ success: false, 'error-codes': ['token-already-used'] });

    const result = TokenService.verifySuccessToken(token, remoteip);
    if (!result.valid) return res.json({ success: false, 'error-codes': [result.error || 'invalid-input-response'] });

    await setWithTTL(usedTokenKey, '1', 600);
    await MetricsService.recordVerification(true, undefined, result.fingerprint);

    return res.json({
      success: true,
      challenge_ts: result.challengeTs,
      hostname: 'captcha-p.asprin.dev',
      fingerprint: result.fingerprint,
      ip: result.ip,
    });
  } catch (error) {
    console.error('[SITEVERIFY] Error:', error);
    return res.status(500).json({ success: false, 'error-codes': ['internal-error'] });
  }
});

// =====================================================
// ADMIN API: Update Rate Limits
// =====================================================
app.post('/api/admin/ratelimit', verifyAdminKey, async (req: Request, res: Response) => {
  try {
    const { endpoint, windowMs, maxRequests, message } = req.body;
    if (!endpoint || !windowMs || !maxRequests) return res.status(400).json({ error: 'Missing required fields' });

    let config = await RateLimitConfigModel.findOne({ endpoint });
    if (!config) config = new RateLimitConfigModel({ endpoint });

    config.windowMs = windowMs;
    config.maxRequests = maxRequests;
    if (message) config.message = message;
    config.updatedAt = new Date();
    await config.save();

    await rateLimitManager.reload(endpoint);
    SecurityLogger.info('Admin updated rate limit', { endpoint });
    res.json({ success: true, config });
  } catch (error) {
    res.status(500).json({ error: 'Update failed' });
  }
});

app.get('/api/admin/ratelimit', verifyAdminKey, async (req: Request, res: Response) => {
  const configs = await RateLimitConfigModel.find({});
  res.json({ success: true, configs });
});

// =====================================================
// METRICS API - SECURED
// =====================================================
app.get('/api/metrics', verifyAdminKey, async (req: Request, res: Response) => {
  try {
    const metrics = await MetricsService.getMetrics();
    const hourlyStats = await MetricsService.getHourlyStats(24);
    res.json({ success: true, timestamp: new Date().toISOString(), metrics, hourlyStats });
  } catch (error) {
    res.status(500).json({ success: false, error: 'Failed to fetch metrics' });
  }
});

// Health check endpoint
app.get('/health', (req: Request, res: Response) => {
  res.status(200).json({ status: 'healthy', timestamp: new Date().toISOString(), service: 'captcha-server' });
});

async function startServer() {
  await connectMongo();
  await rateLimitManager.init();
  app.listen(PORT, () => {
    console.log(`Server is running at http://localhost:${PORT}`);
  });
}
startServer();
