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
    // Allow requests with no origin (like direct image loads, curl, server-to-server)
    if (!origin) {
      return callback(null, true);
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

// CSRF token middleware
app.use(csrfTokenMiddleware);

// In-memory store for challenges (use Redis in production)
const challengeStore = new Map<
  string,
  { challenge: ReturnType<typeof CaptchaGenerator.generateChallenge>; fingerprint: string; ip: string }
>();

// Route to get captcha challenge
app.get('/captcha', challengeRateLimiter, (req: Request, res: Response) => {
  try {
    // Check for headless browser
    const userAgent = req.headers['user-agent'] || '';
    const isHeadless = BehaviorAnalyzer.detectHeadlessBrowser(
      userAgent,
      req.headers as Record<string, string>
    );

    if (isHeadless) {
      return res.status(403).json({
        success: false,
        message: 'Automated requests are not allowed',
      });
    }

    // Generate challenge
    const challenge = CaptchaGenerator.generateChallenge();
    if (!challenge) {
      return res.status(500).json({
        success: false,
        message: 'Failed to generate challenge',
      });
    }

    // Get fingerprint and IP
    const fingerprint = req.fingerprint?.hash || 'unknown';
    const ip = req.fingerprint?.components.ip || 'unknown';

    // Generate token
    const tokenResponse = TokenService.generateToken(
      challenge.id,
      fingerprint,
      ip
    );

    // Store challenge
    challengeStore.set(challenge.id, {
      challenge,
      fingerprint,
      ip,
    });

    // Clean up expired challenges periodically
    setTimeout(() => {
      challengeStore.delete(challenge.id);
    }, 5 * 60 * 1000);

    // Store challenge ID and token in response headers
    res.setHeader('X-Challenge-Id', challenge.id);
    res.setHeader('X-Token', tokenResponse.token);
    res.setHeader('X-CSRF-Token', req.csrfToken || '');
    res.setHeader('X-Expires-In', tokenResponse.expiresIn.toString());

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
  csrfVerificationMiddleware,
  (req: Request, res: Response) => {
    try {
      const { captcha, token, challengeId, behaviorData } = req.body;

      // Validate input
      if (!captcha || !token || !challengeId) {
        return res.json({
          success: false,
          message: 'Missing required fields',
        });
      }

      // Get fingerprint and IP
      const fingerprint = req.fingerprint?.hash || 'unknown';
      const ip = req.fingerprint?.components.ip || 'unknown';

      // Verify token
      const tokenVerification = TokenService.verifyToken(
        token,
        fingerprint,
        ip
      );

      if (!tokenVerification.valid) {
        return res.json({
          success: false,
          message: tokenVerification.error || 'Token verification failed',
        });
      }

      // Get challenge from store
      const stored = challengeStore.get(challengeId);
      if (!stored) {
        return res.json({
          success: false,
          message: 'Challenge not found or expired',
        });
      }

      // Check if challenge is expired
      if (CaptchaGenerator.isExpired(stored.challenge!)) {
        challengeStore.delete(challengeId);
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
        return res.json({
          success: false,
          message: 'Request origin mismatch',
        });
      }

      // Analyze behavior if provided
      if (behaviorData) {
        const behaviorScore = BehaviorAnalyzer.analyzeBehavior(behaviorData);
        if (behaviorScore.riskLevel === 'high') {
          challengeStore.delete(challengeId);
          return res.json({
            success: false,
            message: 'Suspicious behavior detected',
          });
        }
      }

      // Verify captcha answer
      if (
        captcha.toLowerCase() === stored.challenge!.text.toLowerCase()
      ) {
        // Clear challenge to prevent reuse
        challengeStore.delete(challengeId);

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
