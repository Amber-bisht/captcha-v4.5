import express, { Request, Response } from 'express';
import cors from 'cors';
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
import { BehaviorAnalyzer } from './utils/behaviorAnalyzer';
import { SecureImageServer, SecureChallenge, createSecureImageMiddleware } from './utils/secureImageServer';

const app = express();
const PORT = process.env.PORT || 3001;

// Allowed origins for CORS
const ALLOWED_ORIGINS = [
  'https://links.asprin.dev',
  'https://www.links.asprin.dev',
  // Development
  'http://localhost:3000',
  'http://localhost:3001',
];

// CAPTCHA Site Key (public) and Secret Key (private)
const CAPTCHA_SITE_KEY = process.env.CAPTCHA_SITE_KEY || 'sk_captcha_asprin_default_site_key';
const CAPTCHA_SECRET_KEY = process.env.CAPTCHA_SECRET_KEY || 'sk_captcha_asprin_default_secret_key';

// Used success tokens store (prevent reuse)
const usedSuccessTokens = new Set<string>();

// Security headers
app.use(helmet({
  crossOriginEmbedderPolicy: false, // Allow images
}));

// CORS - Strict origin whitelist
app.use(cors({
  origin: (origin, callback) => {
    // Allow requests with no origin (mobile apps, curl, etc.) only in development
    if (!origin) {
      if (process.env.NODE_ENV !== 'production') {
        return callback(null, true);
      }
      return callback(new Error('No origin header'), false);
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

app.use(express.json());
app.use(cookieParser());

// Serve static files EXCEPT images (images served securely)
app.use(express.static(path.join(__dirname, '../public'), {
  index: 'index.html',
  // Don't serve images directory directly
  setHeaders: (res, filePath) => {
    if (filePath.includes('/images/')) {
      res.status(403);
    }
  }
}));

// Block direct access to images directory
app.use('/images', (req, res) => {
  res.status(403).json({ error: 'Direct image access forbidden' });
});

// Session configuration
app.use(createSessionMiddleware());

// Fingerprint middleware (must be before routes)
app.use(fingerprintMiddleware);

// CSRF token middleware
app.use(csrfTokenMiddleware);

// Initialize secure image server
const secureImageServer = new SecureImageServer(path.join(__dirname, '../public/images'));

// In-memory store for challenges (use Redis in production)
const challengeStore = new Map<
  string,
  {
    challenge: SecureChallenge;
    fingerprint: string;
    ip: string;
  }
>();

// =====================================================
// SECURE IMAGE ENDPOINT - Serves images with random IDs
// =====================================================
app.get('/api/image/:imageId', createSecureImageMiddleware(secureImageServer));

// =====================================================
// CAPTCHA CHALLENGE ENDPOINT
// =====================================================
app.get('/api/captcha', challengeRateLimiter, (req: Request, res: Response) => {
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
        error: 'Automated requests are not allowed',
      });
    }

    // Generate SECURE challenge (with randomized image IDs)
    const challenge = secureImageServer.generateSecureChallenge(9);

    if (!challenge) {
      return res.status(500).json({
        error: 'No valid categorized images found.',
      });
    }

    // Get fingerprint and IP
    const fingerprint = req.fingerprint?.hash || 'unknown';
    const ip = req.fingerprint?.components.ip || 'unknown';

    // Generate token
    const tokenResponse = TokenService.generateToken(
      challenge.sessionId,
      fingerprint,
      ip
    );

    // Store challenge
    challengeStore.set(challenge.sessionId, {
      challenge,
      fingerprint,
      ip,
    });

    // Clean up expired challenges periodically
    setTimeout(() => {
      challengeStore.delete(challenge.sessionId);
    }, 5 * 60 * 1000);

    // Return challenge with SECURE image URLs (random IDs, not real filenames)
    res.json({
      success: true,
      sessionId: challenge.sessionId,
      question: challenge.question,
      // SECURITY: Return URLs with random IDs, not actual filenames
      images: challenge.imageIds.map(id => ({
        id,
        url: `/api/image/${id}`,
      })),
      token: tokenResponse.token,
      csrfToken: req.csrfToken,
      expiresIn: tokenResponse.expiresIn,
    });
  } catch (error) {
    console.error('Error generating challenge:', error);
    res.status(500).json({
      success: false,
      error: 'Internal server error',
    });
  }
});

// =====================================================
// VERIFICATION ENDPOINT
// =====================================================
app.post(
  '/api/verify',
  verificationRateLimiter,
  csrfVerificationMiddleware,
  (req: Request, res: Response) => {
    try {
      const { sessionId, selectedImages, token, behaviorData } = req.body;

      // Validate input
      if (!sessionId || !selectedImages || !token) {
        return res.status(400).json({
          success: false,
          message: 'Missing required fields',
        });
      }

      // Get challenge from store
      const stored = challengeStore.get(sessionId);
      if (!stored) {
        return res.status(400).json({
          success: false,
          message: 'Invalid or expired session',
        });
      }

      // Check if challenge is expired
      if (Date.now() > stored.challenge.expiresAt) {
        challengeStore.delete(sessionId);
        return res.status(400).json({
          success: false,
          message: 'Challenge expired',
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
        return res.status(400).json({
          success: false,
          message: tokenVerification.error || 'Token verification failed',
        });
      }

      // Verify fingerprint and IP match
      if (stored.fingerprint !== fingerprint || stored.ip !== ip) {
        return res.status(400).json({
          success: false,
          message: 'Request origin mismatch',
        });
      }

      // Analyze behavior if provided
      if (behaviorData) {
        const behaviorScore = BehaviorAnalyzer.analyzeBehavior(behaviorData);
        if (behaviorScore.riskLevel === 'high') {
          challengeStore.delete(sessionId);
          return res.json({
            success: false,
            message: 'Suspicious behavior detected',
          });
        }
      }

      // Verify answer using SECURE image IDs
      const result = secureImageServer.verifyAnswers(sessionId, selectedImages);

      if (result.correct) {
        // Correct
        challengeStore.delete(sessionId); // Clear session to prevent replay

        // Generate success token
        const successToken = TokenService.generateSuccessToken(
          fingerprint,
          ip
        );

        res.json({
          success: true,
          message: 'Captcha verified successfully!',
          token: successToken.token,
        });
      } else {
        res.json({
          success: false,
          message: result.message,
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

// =====================================================
// SERVER-SIDE TOKEN VERIFICATION (Like Cloudflare siteverify)
// Backend calls this with secret key to verify user's token
// =====================================================
app.post('/api/siteverify', (req: Request, res: Response) => {
  try {
    const { secret, response: userToken, remoteip } = req.body;

    // Validate secret key
    if (!secret || secret !== CAPTCHA_SECRET_KEY) {
      return res.status(401).json({
        success: false,
        'error-codes': ['invalid-secret'],
        message: 'Invalid secret key',
      });
    }

    // Validate token exists
    if (!userToken) {
      return res.status(400).json({
        success: false,
        'error-codes': ['missing-input-response'],
        message: 'Missing captcha response token',
      });
    }

    // Check if token has already been used (prevent replay)
    if (usedSuccessTokens.has(userToken)) {
      return res.status(400).json({
        success: false,
        'error-codes': ['token-already-used'],
        message: 'This token has already been used',
      });
    }

    // Verify the JWT token
    const jwt = require('jsonwebtoken');
    const JWT_SECRET = process.env.JWT_SECRET || 'default-jwt-secret';

    try {
      const decoded = jwt.verify(userToken, JWT_SECRET);

      // Mark token as used (prevent reuse)
      usedSuccessTokens.add(userToken);

      // Clean up used token after expiry time (10 minutes)
      setTimeout(() => {
        usedSuccessTokens.delete(userToken);
      }, 10 * 60 * 1000);

      // Optionally verify IP if provided
      if (remoteip && decoded.ip && decoded.ip !== remoteip && decoded.ip !== 'unknown') {
        console.warn(`IP mismatch: token=${decoded.ip}, request=${remoteip}`);
        // We log but don't fail - IPs can change due to proxies
      }

      return res.json({
        success: true,
        challenge_ts: new Date(decoded.timestamp).toISOString(),
        hostname: 'captcha-p.asprin.dev',
        'error-codes': [],
      });
    } catch (jwtError: any) {
      if (jwtError.name === 'TokenExpiredError') {
        return res.status(400).json({
          success: false,
          'error-codes': ['token-expired'],
          message: 'Token has expired',
        });
      }

      return res.status(400).json({
        success: false,
        'error-codes': ['invalid-input-response'],
        message: 'Invalid or malformed token',
      });
    }
  } catch (error) {
    console.error('Siteverify error:', error);
    return res.status(500).json({
      success: false,
      'error-codes': ['internal-error'],
      message: 'Internal server error',
    });
  }
});

// =====================================================
// GET SITE KEY (Public endpoint for frontend)
// =====================================================
app.get('/api/sitekey', (req: Request, res: Response) => {
  res.json({
    success: true,
    siteKey: CAPTCHA_SITE_KEY,
  });
});

// Health check endpoint
app.get('/health', (req: Request, res: Response) => {
  res.status(200).json({
    status: 'healthy',
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    service: 'captcha-image-secure',
  });
});

app.listen(PORT, () => {
  console.log(`Secure Image CAPTCHA Server running at http://localhost:${PORT}`);
});
