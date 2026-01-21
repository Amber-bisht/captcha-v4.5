import express, { Request, Response } from 'express';
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
import RedisStore from './utils/redisStore';

const app = express();
const PORT = process.env.PORT || 3001;

// Allowed origins for CORS
const ALLOWED_ORIGINS = [
  'https://links.asprin.dev',
  'https://www.links.asprin.dev',
  'http://localhost:3000',
  'http://localhost:3001',
];

// CAPTCHA Keys
const CAPTCHA_SITE_KEY = process.env.CAPTCHA_SITE_KEY || 'sk_captcha_asprin_default_site_key';
const CAPTCHA_SECRET_KEY = process.env.CAPTCHA_SECRET_KEY || 'sk_captcha_asprin_default_secret_key';
const JWT_SECRET = process.env.JWT_SECRET || 'default-jwt-secret';

// Security headers
app.use(helmet({
  crossOriginEmbedderPolicy: false,
  crossOriginResourcePolicy: { policy: "cross-origin" },
}));

// CORS
app.use(cors({
  origin: (origin, callback) => {
    if (!origin || ALLOWED_ORIGINS.includes(origin)) {
      return callback(null, true);
    }
    return callback(new Error('Not allowed by CORS'), false);
  },
  credentials: true,
  methods: ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'X-CSRF-Token', 'X-Captcha-Site-Key', 'Authorization'],
}));

app.use(express.json());
app.use(cookieParser());

// Static files
app.use(express.static(path.join(__dirname, '../public')));

// Session & Fingerprint
app.use(createSessionMiddleware());
app.use(fingerprintMiddleware);

// Initialize generators
const secureImageServer = new SecureImageServer(path.join(__dirname, '../public/images'));
const dynamicCaptchaGenerator = new DynamicCaptchaGenerator();

// =====================================================
// DYNAMIC TEXT CAPTCHA (20-FACTOR SYSTEM)
// =====================================================
app.get('/api/dynamic-captcha', challengeRateLimiter, async (req: Request, res: Response) => {
  try {
    const result = await dynamicCaptchaGenerator.generate();
    const serverFingerprint = generateServerFingerprint(req);
    const ip = (req.headers['x-forwarded-for'] as string)?.split(',')[0] || req.socket.remoteAddress || 'unknown';

    const tokenResponse = TokenService.generateToken(result.id, serverFingerprint, ip);

    await RedisStore.setChallenge(result.id, {
      textAnswer: result.answer,
      type: 'text',
      fingerprint: serverFingerprint,
      ip,
      expiresAt: result.expiresAt
    });

    res.setHeader('X-Token', tokenResponse.token);
    res.setHeader('X-Challenge-Id', result.id);
    res.setHeader('Content-Type', 'image/jpeg');
    res.send(result.image);
  } catch (error) {
    console.error('Dynamic captcha error:', error);
    res.status(500).json({ error: 'Failed to generate captcha' });
  }
});

// =====================================================
// IMAGE CAPTCHA ENDPOINT
// =====================================================
app.get('/api/captcha', challengeRateLimiter, async (req: Request, res: Response) => {
  try {
    const challenge = await secureImageServer.generateSecureChallenge({ gridSize: 9, difficulty: 'standard' });
    if (!challenge) return res.status(500).json({ error: 'Failed to generate challenge' });

    const serverFingerprint = generateServerFingerprint(req);
    const ip = (req.headers['x-forwarded-for'] as string)?.split(',')[0] || req.socket.remoteAddress || 'unknown';

    const tokenResponse = TokenService.generateToken(challenge.sessionId, serverFingerprint, ip);

    await RedisStore.setChallenge(challenge.sessionId, {
      challenge,
      type: 'image',
      fingerprint: serverFingerprint,
      ip,
      expiresAt: challenge.expiresAt
    });

    res.json({
      success: true,
      sessionId: challenge.sessionId,
      question: challenge.question,
      images: challenge.imageIds.map(id => ({ id, url: `/api/image/${id}` })),
      token: tokenResponse.token,
    });
  } catch (error) {
    res.status(500).json({ success: false, error: 'Internal server error' });
  }
});

app.get('/api/image/:imageId', createSecureImageMiddleware(secureImageServer));

// =====================================================
// VERIFICATION ENDPOINT (HANDLES BOTH TYPES)
// =====================================================
app.post('/api/verify', verificationRateLimiter, async (req: Request, res: Response) => {
  try {
    const { sessionId, selectedImages, textAnswer, token, behaviorData } = req.body;
    const challengeId = sessionId || req.headers['x-challenge-id'] as string;

    if (!challengeId || !token) {
      return res.status(400).json({ success: false, message: 'Missing fields' });
    }

    const stored = await RedisStore.getChallenge(challengeId);
    if (!stored || Date.now() > stored.expiresAt) {
      return res.status(400).json({ success: false, message: 'Expired or invalid' });
    }

    const serverFingerprint = generateServerFingerprint(req);
    const ip = (req.headers['x-forwarded-for'] as string)?.split(',')[0] || req.socket.remoteAddress || 'unknown';

    const tokenVerification = await TokenService.verifyToken(token, serverFingerprint, ip);
    if (!tokenVerification.valid) {
      return res.status(400).json({ success: false, message: tokenVerification.error });
    }

    let isCorrect = false;
    if (stored.type === 'text') {
      isCorrect = textAnswer?.toLowerCase() === stored.textAnswer?.toLowerCase();
    } else {
      const result = await secureImageServer.verifyAnswers(challengeId, selectedImages);
      isCorrect = result.correct;
    }

    if (isCorrect) {
      await RedisStore.deleteChallenge(challengeId);
      const successToken = TokenService.generateSuccessToken(serverFingerprint, ip);
      return res.json({ success: true, token: successToken.token });
    }

    res.json({ success: false, message: 'Incorrect answer' });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Internal error' });
  }
});

// =====================================================
// SERVER-SIDE VERIFY (FOR CLIENTS)
// =====================================================
app.post('/api/siteverify', async (req: Request, res: Response) => {
  try {
    const { secret, response: userToken, remoteip } = req.body;
    if (secret !== CAPTCHA_SECRET_KEY) return res.status(401).json({ success: false, 'error-codes': ['invalid-secret'] });

    const decoded = jwt.verify(userToken, JWT_SECRET) as any;

    // SECURITY FIX: Only allow tokens with status 'verified' to pass siteverify
    // This prevents attackers from using challenge-issued tokens to skip verification
    if (decoded.status !== 'verified') {
      return res.status(400).json({
        success: false,
        'error-codes': ['token-not-verified'],
        message: 'This token has not been solved yet.'
      });
    }

    // IP BINDING CHECK: Ensure token is used by the same IP that solved it
    if (remoteip && decoded.ip && decoded.ip !== remoteip) {
      return res.status(400).json({
        success: false,
        'error-codes': ['ip-mismatch'],
        message: 'Request origin mismatch.'
      });
    }

    if (await RedisStore.isTokenUsed(userToken)) return res.status(400).json({ success: false, 'error-codes': ['token-already-used'] });

    await RedisStore.markTokenUsed(userToken);
    return res.json({ success: true, challenge_ts: new Date(decoded.timestamp).toISOString() });
  } catch {
    return res.status(400).json({ success: false, 'error-codes': ['invalid-token'] });
  }
});

app.get('/api/sitekey', (req, res) => res.json({ success: true, siteKey: CAPTCHA_SITE_KEY }));

app.get('/health', (req, res) => res.json({ status: 'healthy', redis: redisClient.status }));

async function startServer() {
  await initRedis();
  app.listen(PORT, () => console.log(`Server running at http://localhost:${PORT}`));
}

startServer();
