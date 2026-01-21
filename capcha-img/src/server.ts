import express, { Request, Response, NextFunction } from 'express';
import cors from 'cors';
import path from 'path';
import helmet from 'helmet';
import cookieParser from 'cookie-parser';
import crypto from 'crypto';
import jwt from 'jsonwebtoken';

import { createSessionMiddleware } from './config/session';
import redisClient, { initRedis } from './config/redis';
import { fingerprintMiddleware, generateServerFingerprint } from './middleware/fingerprint';
import {
  challengeRateLimiter,
  verificationRateLimiter,
} from './middleware/rateLimiter';
import { TokenService } from './utils/tokenService';
import { BehaviorAnalyzer } from './utils/behaviorAnalyzer';
import { SecureImageServer, createSecureImageMiddleware } from './utils/secureImageServer';
import { DynamicCaptchaGenerator } from './utils/dynamicCaptcha';
import { SpatialCaptchaGenerator } from './utils/spatialCaptcha';
import RedisStore from './utils/redisStore';
import { PoWManager } from './security/powManager';
import { RiskAnalyzer } from './security/riskAnalyzer';

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
const JWT_SECRET = process.env.JWT_SECRET || 'default-jwt-secret';

app.use(helmet({ crossOriginEmbedderPolicy: false, crossOriginResourcePolicy: { policy: "cross-origin" } }));
app.use(cors({
  origin: (origin, callback) => { if (!origin || ALLOWED_ORIGINS.includes(origin)) return callback(null, true); return callback(new Error('CORS blocked'), false); },
  credentials: true,
  methods: ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'X-CSRF-Token', 'X-Captcha-Site-Key', 'Authorization', 'X-PoW-Solution', 'X-PoW-Nonce'],
}));
app.use(express.json());
app.use(cookieParser());
app.use(createSessionMiddleware());
app.use(fingerprintMiddleware);

// =====================================================
// BOT KILLER MIDDLEWARE: Header Integrity & Jitter
// =====================================================
const botKiller = async (req: Request, res: Response, next: NextFunction) => {
  const ua = req.headers['user-agent'] || '';
  const risk = await RiskAnalyzer.calculateRiskScore(req);

  // 1. Instant block for obvious bot headers
  if (req.headers['navigator-webdriver'] || req.headers['x-automation-id'] || ua.includes('HeadlessChrome')) {
    console.warn(`[BLOCKED] Bot headers detected from IP: ${req.ip}`);
    return res.status(403).json({ error: 'Security violation' });
  }

  // 2. Temporal Jitter: Waste attacker time for suspicious requests
  if (risk.score > 40) {
    const delay = Math.floor(Math.random() * 2000) + 500; // 0.5s to 2.5s delay
    await new Promise(resolve => setTimeout(resolve, delay));
  }

  next();
};

const secureImageServer = new SecureImageServer(path.join(__dirname, '../public/images'));
const dynamicCaptchaGenerator = new DynamicCaptchaGenerator();
const spatialGenerator = new SpatialCaptchaGenerator();

// =====================================================
// 1. INITIALIZE CHALLENGE (Get PoW requirements)
// =====================================================
app.get('/api/init', botKiller, async (req: Request, res: Response) => {
  try {
    const risk = await RiskAnalyzer.calculateRiskScore(req);

    // ECONOMIC TAX: Datacenters/VPNs get much harder PoW
    let difficultyAdjustment = 0;
    if (risk.level === 'high') difficultyAdjustment = 1;
    if (risk.level === 'critical') difficultyAdjustment = 2;

    const challengeBoundary = PoWManager.generateChallenge(risk.score);
    challengeBoundary.difficulty += difficultyAdjustment;

    await RedisStore.setPoWChallenge(challengeBoundary.nonce, challengeBoundary.difficulty);

    res.json({
      nonce: challengeBoundary.nonce,
      difficulty: challengeBoundary.difficulty,
      riskLevel: risk.level,
      recommendedChallenge: risk.challengeConfig.recommendedChallenge
    });
  } catch (err) {
    res.status(500).json({ error: 'Init failed' });
  }
});

// =====================================================
// 2. REQUEST CHALLENGE (Hybrid Flow)
// =====================================================
app.post('/api/request-challenge', botKiller, challengeRateLimiter, async (req: Request, res: Response) => {
  try {
    const { nonce, solution, type } = req.body;

    const difficulty = await RedisStore.consumePoWChallenge(nonce);
    if (difficulty === null) return res.status(403).json({ error: 'Invalid or expired nonce' });

    const isValidPoW = PoWManager.verify(nonce, solution, difficulty);
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
// 3. VERIFICATION
// =====================================================
app.post('/api/verify', botKiller, verificationRateLimiter, async (req: Request, res: Response) => {
  try {
    const { sessionId, textAnswer, targetFrame, token, honeyPot } = req.body;

    if (honeyPot) {
      // PERMANENT RATE LIMIT / REDIS BAN could go here
      return res.status(403).json({ success: false, message: 'Violation tracked' });
    }

    const challengeId = sessionId;
    if (!challengeId || !token) return res.status(400).json({ success: false, message: 'Missing fields' });

    const stored = await RedisStore.getChallenge(challengeId);
    if (!stored || Date.now() > stored.expiresAt) return res.status(400).json({ success: false, message: 'Expired' });

    const serverFingerprint = generateServerFingerprint(req);
    const ip = (req.headers['x-forwarded-for'] as string)?.split(',')[0] || req.socket.remoteAddress || 'unknown';

    const tokenVerification = await TokenService.verifyToken(token, serverFingerprint, ip);
    if (!tokenVerification.valid) return res.status(400).json({ success: false, message: tokenVerification.error });

    let isCorrect = false;
    const solveTime = Date.now() - (stored.expiresAt - 300000);

    if (stored.type === 'spatial') {
      isCorrect = parseInt(targetFrame, 10) === stored.targetFrame;
      // 3D rotation requires at least 2.5s for a real human
      if (solveTime < 2500) isCorrect = false;
    } else {
      isCorrect = textAnswer?.toLowerCase() === stored.textAnswer?.toLowerCase();
      // Text entry requires at least 1.5s
      if (solveTime < 1500) isCorrect = false;
    }

    if (isCorrect) {
      await RedisStore.deleteChallenge(challengeId);
      const successToken = TokenService.generateSuccessToken(serverFingerprint, ip);
      return res.json({ success: true, token: successToken.token });
    }

    res.json({ success: false, message: 'Incorrect' });
  } catch (error) {
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

app.get('/api/sitekey', (req, res) => res.json({ success: true, siteKey: CAPTCHA_SITE_KEY }));
app.get('/health', (req, res) => res.json({ status: 'healthy', redis: redisClient.status }));

async function startServer() {
  await initRedis();
  app.listen(PORT, () => console.log(`Hydra Anti-Bot Server running on ${PORT}`));
}
startServer();
