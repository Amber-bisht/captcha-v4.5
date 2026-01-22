import express, { Request, Response, NextFunction } from 'express';
import mongoose from 'mongoose';
import cors from 'cors';
import path from 'path';
import helmet from 'helmet';
import cookieParser from 'cookie-parser';
import crypto from 'crypto';
import jwt from 'jsonwebtoken';

import { createSessionMiddleware } from './config/session';
import redisClient, { initRedis } from './config/redis';
import { connectMongo } from './config/mongo'; // NEW
import { fingerprintMiddleware, generateServerFingerprint, analyzeFingerprint } from './middleware/fingerprint';
import {
  challengeRateLimiter,
  verificationRateLimiter,
  rateLimitManager // NEW
} from './middleware/rateLimiter';
import { TokenService } from './utils/tokenService';
import { BehaviorAnalyzer } from './utils/behaviorAnalyzer';
import { SecureImageServer, createSecureImageMiddleware } from './utils/secureImageServer';
import { DynamicCaptchaGenerator } from './utils/dynamicCaptcha';
import { SpatialCaptchaGenerator } from './utils/spatialCaptcha';
import RedisStore from './utils/redisStore';
import { PoWManager } from './security/powManager';
import { RiskAnalyzer } from './security/riskAnalyzer';
import { deviceReputation } from './security/deviceReputation';
import { SecurityLogger } from './utils/securityLogger';
import { MetricsService } from './utils/metricsService';
import RateLimitConfigModel from './models/RateLimitConfig';
import AdminKeyModel from './models/AdminKey';

const app = express();
const PORT = process.env.PORT || 3001;

// Allowed origins
const ALLOWED_ORIGINS = [
  'https://links.asprin.dev',
  'https://www.links.asprin.dev',
  'http://localhost:3000',
  'http://localhost:3001',
];

const CAPTCHA_SITE_KEY = process.env.CAPTCHA_SITE_KEY || 'sk_captcha_asprin_default_site_key';
const CAPTCHA_SECRET_KEY = process.env.CAPTCHA_SECRET_KEY || 'sk_captcha_asprin_default_secret_key';

// SECURITY FIX C3: Require JWT_SECRET to be explicitly set - no fallback
const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) {
  console.error('[FATAL] JWT_SECRET environment variable is required but not set');
  process.exit(1);
}

app.use(helmet({ crossOriginEmbedderPolicy: false, crossOriginResourcePolicy: { policy: "cross-origin" } }));
app.use(cors({
  origin: (origin, callback) => {
    // SECURITY NOTE: Server-to-server requests (like from Next.js API) often lack Origin
    // Bots can forge Origin anyway, so this check mainly hurts legitimate backend calls
    if (!origin) return callback(null, true);

    if (ALLOWED_ORIGINS.includes(origin)) return callback(null, true);
    return callback(new Error('CORS blocked'), false);
  },
  credentials: true,
  methods: ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'X-CSRF-Token', 'X-Captcha-Site-Key', 'Authorization', 'X-PoW-Solution', 'X-PoW-Nonce', 'x-admin-key'],
}));
app.use(express.json());
app.use(cookieParser());
app.use(createSessionMiddleware());
app.use(fingerprintMiddleware);

// =====================================================
// BOT KILLER MIDDLEWARE: Automation Detection
// CAREFUL: Avoid false positives that block real users
// =====================================================
const BOT_USER_AGENTS = [
  // Automation tools - SPECIFIC patterns only
  'python-requests', 'python-urllib', 'aiohttp/', 'httpx/',
  'curl/', 'wget/', 'libcurl/', 'httpie/',
  'node-fetch/', 'axios/', 'got/', 'superagent/',
  'apache-httpclient', 'okhttp/',
  'go-http-client/',
  'guzzlehttp', 'php-curl',
  // Headless browsers - high confidence patterns
  'headlesschrome', 'phantomjs', 'slimerjs',
  'puppeteer', 'playwright',
  // Generic bots - ONLY very specific patterns
  'scrapy/', 'crawler/', 'spider/'
  // NOTE: Removed broad patterns like 'bot', 'python', '' that cause false positives
];

const botKiller = async (req: Request, res: Response, next: NextFunction) => {
  const ua = (req.headers['user-agent'] || '').toLowerCase();

  // Skip bot check if UA looks like a real browser
  const looksLikeBrowser = ua.includes('mozilla/') && (
    ua.includes('chrome/') ||
    ua.includes('firefox/') ||
    ua.includes('safari/') ||
    ua.includes('edge/')
  );

  if (looksLikeBrowser) {
    // Real browser - just check for automation markers
    if (
      req.headers['navigator-webdriver'] ||
      req.headers['sec-webdriver'] === 'true' ||
      ua.includes('headlesschrome')
    ) {
      SecurityLogger.warn('Blocked Headless Browser', { ip: req.ip, type: 'headless_browser_detected', details: ua });
      return res.status(403).json({ error: 'Security violation' });
    }

    // Let real browsers through without delay
    return next();
  }

  // Non-browser UA - check against bot list
  const isKnownBot = BOT_USER_AGENTS.some(pattern => ua.includes(pattern));
  if (isKnownBot) {
    SecurityLogger.warn('Blocked Known Bot', { ip: req.ip, type: 'bot_ua_detected', details: ua });
    return res.status(403).json({
      error: 'Access denied',
      code: 'BOT_DETECTED'
    });
  }

  // Unknown non-browser UA - apply risk-based delay but don't block
  const risk = await RiskAnalyzer.calculateRiskScore(req);
  if (risk.score > 50) {
    const delay = Math.min(Math.floor(risk.score * 30), 3000); // Up to 3s delay
    await new Promise(resolve => setTimeout(resolve, delay));
  }

  next();
};

const secureImageServer = new SecureImageServer(path.join(__dirname, '../public/images'));
const dynamicCaptchaGenerator = new DynamicCaptchaGenerator();
const spatialGenerator = new SpatialCaptchaGenerator();

// =====================================================
// ADMIN MIDDLEWARE
// =====================================================
const verifyAdminKey = async (req: Request, res: Response, next: NextFunction) => {
  const apiKey = req.headers['x-admin-key'] as string;
  if (!apiKey) return res.status(401).json({ error: 'Missing admin key' });

  // Hash provided key
  const hashed = crypto.createHash('sha256').update(apiKey).digest('hex');
  const validKey = await AdminKeyModel.findOne({ keyHash: hashed });

  if (!validKey) {
    SecurityLogger.warn('Invalid Admin Access Attempt', { ip: req.ip });
    return res.status(403).json({ error: 'Invalid admin key' });
  }

  next();
};

// =====================================================
// 1. INITIALIZE CHALLENGE (Get PoW requirements)
// =====================================================
app.get('/api/init', botKiller, async (req: Request, res: Response) => {
  try {
    const risk = await RiskAnalyzer.calculateRiskScore(req);

    // ECONOMIC TAX: Datacenters/VPNs get much harder PoW
    // Scrypt is now used for high risk, so simple difficulty adjustment logic 
    // is replaced by RiskAnalyzer's recommendation

    // Generate challenge based on recommendation (sha256 or scrypt)
    const useScrypt = risk.challengeConfig.powAlgorithm === 'scrypt';
    const challengeBoundary = PoWManager.generateChallenge(
      risk.score,
      useScrypt
    );

    // Store challenge params in Redis
    await RedisStore.setPoWChallenge(challengeBoundary.nonce, {
      difficulty: challengeBoundary.difficulty,
      algorithm: challengeBoundary.algorithm,
      scryptParams: challengeBoundary.scryptParams
    });

    res.json({
      nonce: challengeBoundary.nonce,
      difficulty: challengeBoundary.difficulty,
      algorithm: challengeBoundary.algorithm,
      scryptParams: challengeBoundary.scryptParams,
      riskLevel: risk.level,
      recommendedChallenge: risk.challengeConfig.recommendedChallenge
    });
  } catch (err) {
    console.error('Init error:', err);
    res.status(500).json({ error: 'Init failed' });
  }
});

// =====================================================
// 2. REQUEST CHALLENGE (Hybrid Flow)
// =====================================================
app.post('/api/request-challenge', botKiller, challengeRateLimiter, async (req: Request, res: Response) => {
  try {
    const { nonce, solution, type } = req.body;

    // Retrieve challenge params from Redis
    const challengeParams = await RedisStore.consumePoWChallenge(nonce);
    if (!challengeParams) return res.status(403).json({ error: 'Invalid or expired nonce' });

    // Verify PoW using stored params (algorithm, difficulty, etc.)
    const isValidPoW = PoWManager.verify(
      nonce,
      solution,
      challengeParams.difficulty,
      challengeParams.algorithm,
      challengeParams.scryptParams
    );

    if (!isValidPoW) return res.status(403).json({ error: 'Security verification failed (PoW)' });

    const serverFingerprint = generateServerFingerprint(req);
    const ip = (req.headers['x-forwarded-for'] as string)?.split(',')[0] || req.socket.remoteAddress || 'unknown';

    const risk = await RiskAnalyzer.calculateRiskScore(req);
    // FORCE SPATIAL for anything medium-high risk
    const targetType = risk.score > 50 ? 'spatial' : (type || 'text');

    let challengeData: any = {};

    if (targetType === 'spatial') {
      const challenge = await spatialGenerator.generate();

      if (!challenge || !challenge.spriteSheet || challenge.spriteSheet.length < 1000) {
        throw new Error('Spatial generation failed');
      }

      const tokenResponse = TokenService.generateToken(challenge.id, serverFingerprint, ip);
      await RedisStore.setChallenge(challenge.id, {
        targetFrame: challenge.targetFrame,
        type: 'spatial',
        fingerprint: serverFingerprint,
        ip,
        expiresAt: challenge.expiresAt
      });
      challengeData = {
        id: challenge.id,
        type: 'spatial',
        spriteSheet: `data:image/png;base64,${challenge.spriteSheet.toString('base64')}`,
        totalFrames: challenge.totalFrames,
        startFrame: challenge.startFrame,
        token: tokenResponse.token
      };
    } else {
      const result = await dynamicCaptchaGenerator.generate();

      if (!result || !result.image || result.image.length < 5000) {
        throw new Error('Dynamic generation failed');
      }

      const tokenResponse = TokenService.generateToken(result.id, serverFingerprint, ip);
      await RedisStore.setChallenge(result.id, {
        textAnswer: result.answer,
        type: 'text',
        fingerprint: serverFingerprint,
        ip,
        expiresAt: result.expiresAt
      });
      challengeData = {
        id: result.id,
        type: 'text',
        image: `data:image/jpeg;base64,${result.image.toString('base64')}`,
        token: tokenResponse.token
      };
    }
    res.json(challengeData);
  } catch (error) {
    console.error('Challenge generation error:', error);
    res.status(500).json({ error: 'Security challenge unavailable. Please refresh.' });
  }
});

// =====================================================
// 3. VERIFICATION - With Device Reputation Tracking
// =====================================================
app.post('/api/verify', botKiller, verificationRateLimiter, async (req: Request, res: Response) => {
  try {
    const { sessionId, textAnswer, targetFrame, token, honeyPot } = req.body;
    const serverFingerprint = generateServerFingerprint(req);
    const ip = (req.headers['x-forwarded-for'] as string)?.split(',')[0] || req.socket.remoteAddress || 'unknown';

    // ===== DEVICE REPUTATION CHECK =====
    const deviceStatus = await deviceReputation.evaluate(serverFingerprint);

    // Block banned devices immediately
    if (deviceStatus.isBanned) {
      await MetricsService.recordSecurityEvent('banned_attempt');
      SecurityLogger.warn('Banned Device Verification Attempt', {
        ip,
        fingerprint: serverFingerprint,
        type: 'device_banned_access'
      });
      return res.status(403).json({
        success: false,
        message: 'Access denied',
        code: 'DEVICE_BANNED'
      });
    }

    // ===== FINGERPRINT CONSISTENCY CHECK =====
    const fingerprintAnalysis = analyzeFingerprint(req);
    if (!fingerprintAnalysis.isConsistent) {
      // Record suspicious activity but don't block (could be legitimate edge cases)
      await deviceReputation.recordSuspiciousActivity(serverFingerprint, {
        type: 'fingerprint_anomaly',
        details: `Header inconsistencies: ${fingerprintAnalysis.anomalies.join(', ')}`,
        severity: fingerprintAnalysis.suspicionScore > 50 ? 'high' : 'medium'
      });
      await MetricsService.recordSecurityEvent('fingerprint_anomaly');
      SecurityLogger.warn('Fingerprint Anomaly Detected', {
        ip,
        fingerprint: serverFingerprint,
        type: 'fingerprint_anomaly',
        details: fingerprintAnalysis.anomalies
      });
    }

    // Honeypot triggered - record high severity suspicious activity
    if (honeyPot) {
      await MetricsService.recordSecurityEvent('honeypot');
      await deviceReputation.recordChallengeAttempt(serverFingerprint, false, ip, {
        type: 'honeypot_triggered',
        details: `Honeypot field filled: ${typeof honeyPot === 'string' ? honeyPot.substring(0, 50) : 'non-string'}`,
        severity: 'high'
      });
      SecurityLogger.warn('Honeypot Triggered', { ip, fingerprint: serverFingerprint, type: 'honeypot_triggered' });
      return res.status(403).json({ success: false, message: 'Violation tracked' });
    }

    const challengeId = sessionId;
    if (!challengeId || !token) {
      await deviceReputation.recordChallengeAttempt(serverFingerprint, false, ip, {
        type: 'missing_fields',
        details: `Missing: ${!challengeId ? 'sessionId' : ''} ${!token ? 'token' : ''}`,
        severity: 'medium'
      });
      return res.status(400).json({ success: false, message: 'Missing fields' });
    }

    const stored = await RedisStore.getChallenge(challengeId);
    if (!stored || Date.now() > stored.expiresAt) {
      await deviceReputation.recordChallengeAttempt(serverFingerprint, false, ip, {
        type: 'expired_challenge',
        details: 'Attempted to use expired or invalid challenge',
        severity: 'low'
      });
      return res.status(400).json({ success: false, message: 'Expired' });
    }

    const tokenVerification = await TokenService.verifyToken(token, serverFingerprint, ip);
    if (!tokenVerification.valid) {
      // Token manipulation is highly suspicious
      await deviceReputation.recordChallengeAttempt(serverFingerprint, false, ip, {
        type: 'token_invalid',
        details: `Token verification failed: ${tokenVerification.error}`,
        severity: 'high'
      });
      return res.status(400).json({ success: false, message: tokenVerification.error });
    }

    let isCorrect = false;
    const solveTime = Date.now() - (stored.expiresAt - 300000);
    let suspiciousActivity: { type: string; details: string; severity: 'low' | 'medium' | 'high' } | undefined;

    if (stored.type === 'spatial') {
      isCorrect = parseInt(targetFrame, 10) === stored.targetFrame;
      // 3D rotation requires at least 2.5s for a real human
      if (solveTime < 2500) {
        suspiciousActivity = {
          type: 'timing_anomaly',
          details: `Spatial CAPTCHA solved in ${solveTime}ms (min: 2500ms)`,
          severity: 'high'
        };
        isCorrect = false;
      }
    } else {
      isCorrect = textAnswer?.toLowerCase() === stored.textAnswer?.toLowerCase();
      // Text entry requires at least 1.5s
      if (solveTime < 1500) {
        suspiciousActivity = {
          type: 'timing_anomaly',
          details: `Text CAPTCHA solved in ${solveTime}ms (min: 1500ms)`,
          severity: 'high'
        };
        isCorrect = false;
      }
    }

    if (isCorrect) {
      // SUCCESS - Record positive reputation
      await deviceReputation.recordChallengeAttempt(serverFingerprint, true, ip);
      await RedisStore.deleteChallenge(challengeId);

      // Generate success token with additional binding
      const successToken = TokenService.generateSuccessToken(serverFingerprint, ip);

      SecurityLogger.info('Challenge Solved', {
        ip,
        fingerprint: serverFingerprint,
        type: 'challenge_success',
        details: { challengeType: stored.type, time: solveTime }
      });

      // Track metrics
      await MetricsService.recordVerification(true, stored.type as 'spatial' | 'text', solveTime);

      return res.json({ success: true, token: successToken.token });
    }

    // FAILURE - Record negative reputation
    await deviceReputation.recordChallengeAttempt(serverFingerprint, false, ip, suspiciousActivity);

    // Check if device should now be challenged more aggressively
    const updatedStatus = await deviceReputation.evaluate(serverFingerprint);
    SecurityLogger.info('Challenge Failed', {
      ip,
      fingerprint: serverFingerprint,
      type: 'challenge_failed',
      details: { reputationAfter: updatedStatus.reputationScore }
    });

    // Track metrics
    await MetricsService.recordVerification(false, stored.type as 'spatial' | 'text');

    res.json({ success: false, message: 'Incorrect' });
  } catch (error) {
    console.error('[CAPTCHA] Verification error:', error);
    res.status(500).json({ success: false, message: 'Internal error' });
  }
});

app.post('/api/siteverify', async (req: Request, res: Response) => {
  try {
    const { secret, response: userToken, remoteip } = req.body;
    if (secret !== CAPTCHA_SECRET_KEY) return res.status(401).json({ success: false, 'error-codes': ['invalid-secret'] });
    const decoded = jwt.verify(userToken, JWT_SECRET) as any;
    if (decoded.status !== 'verified') return res.status(400).json({ success: false, 'error-codes': ['token-not-verified'] });
    if (remoteip && decoded.ip && decoded.ip !== remoteip) return res.status(400).json({ success: false, 'error-codes': ['ip-mismatch'] });
    if (await RedisStore.isTokenUsed(userToken)) return res.status(400).json({ success: false, 'error-codes': ['token-already-used'] });
    await RedisStore.markTokenUsed(userToken);
    return res.json({ success: true, challenge_ts: new Date(decoded.timestamp).toISOString() });
  } catch { return res.status(400).json({ success: false, 'error-codes': ['invalid-token'] }); }
});

// =====================================================
// ADMIN API: Update Rate Limits
// =====================================================
app.post('/api/admin/ratelimit', verifyAdminKey, async (req: Request, res: Response) => {
  try {
    const { endpoint, windowMs, maxRequests, message } = req.body;

    if (!endpoint || !windowMs || !maxRequests) {
      return res.status(400).json({ error: 'Missing required fields' });
    }

    let config = await RateLimitConfigModel.findOne({ endpoint });
    if (!config) {
      config = new RateLimitConfigModel({ endpoint });
    }

    config.windowMs = windowMs;
    config.maxRequests = maxRequests;
    if (message) config.message = message;
    config.updatedAt = new Date();
    await config.save();

    // Reload in memory
    await rateLimitManager.reload(endpoint);

    SecurityLogger.info('Rate Limit Updated', {
      ip: req.ip,
      type: 'admin_config_update',
      details: { endpoint, maxRequests, windowMs }
    });

    res.json({ success: true, config });
  } catch (error) {
    console.error('Admin update error:', error);
    res.status(500).json({ error: 'Update failed' });
  }
});

// =====================================================
// ADMIN API: List Rate Limits
// =====================================================
app.get('/api/admin/ratelimit', verifyAdminKey, async (req: Request, res: Response) => {
  const configs = await RateLimitConfigModel.find({});
  res.json({ success: true, configs });
});

app.get('/api/sitekey', (req, res) => res.json({ success: true, siteKey: CAPTCHA_SITE_KEY }));
app.get('/health', (req, res) => {
  const mongoStatus = mongoose.connection.readyState;
  const statusMap = {
    0: 'disconnected',
    1: 'connected',
    2: 'connecting',
    3: 'disconnecting',
  };

  const isHealthy = mongoStatus === 1 && redisClient.status === 'ready';
  const httpStatus = isHealthy ? 200 : 503;

  res.status(httpStatus).json({
    status: isHealthy ? 'healthy' : 'unhealthy',
    timestamp: new Date().toISOString(),
    service: 'capcha-img',
    mongo: {
      state: statusMap[mongoStatus as 0 | 1 | 2 | 3] || 'unknown',
      readyState: mongoStatus,
      host: mongoose.connection.host
    },
    redis: redisClient.status
  });
});

// =====================================================
// METRICS ENDPOINT - For monitoring dashboards
// =====================================================
app.get('/api/metrics', verifyAdminKey, async (req: Request, res: Response) => {
  try {
    const metrics = await MetricsService.getMetrics();
    const hourlyStats = await MetricsService.getHourlyStats(24);

    res.json({
      success: true,
      timestamp: new Date().toISOString(),
      metrics,
      hourlyStats,
    });
  } catch (error) {
    console.error('[METRICS] Error fetching metrics:', error);
    res.status(500).json({ success: false, error: 'Failed to fetch metrics' });
  }
});


async function startServer() {
  await connectMongo(); // Connect DB
  await initRedis();
  await rateLimitManager.init(); // Load dynamic rates
  app.listen(PORT, () => console.log(`Hydra Anti-Bot Server running on ${PORT}`));
}
startServer();
