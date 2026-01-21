import rateLimit from 'express-rate-limit';
import { Request, Response } from 'express';
import { RateLimitConfig } from '../types/rateLimit';

/**
 * Create a rate limiter middleware
 */
export function createRateLimiter(config: RateLimitConfig) {
  return rateLimit({
    windowMs: config.windowMs,
    max: config.maxRequests,
    message: config.message || 'Too many requests, please try again later.',
    standardHeaders: config.standardHeaders ?? true,
    legacyHeaders: config.legacyHeaders ?? false,
    // Custom key generator to include fingerprint
    keyGenerator: (req: Request): string => {
      const ip = req.ip || req.socket.remoteAddress || 'unknown';
      const fingerprint = req.fingerprint?.hash || '';
      return `${ip}:${fingerprint}`;
    },
    // Custom handler
    handler: (req: Request, res: Response) => {
      res.status(429).json({
        success: false,
        message: config.message || 'Too many requests, please try again later.',
      });
    },
  });
}

/**
 * Challenge rate limiter: 60 requests per hour (1 per minute)
 */
export const challengeRateLimiter = createRateLimiter({
  windowMs: 60 * 60 * 1000, // 1 hour
  maxRequests: 20,
  message: 'Too many challenge requests. Please try again later.',
});

/**
 * Verification rate limiter: 120 requests per hour (2 per minute)
 */
export const verificationRateLimiter = createRateLimiter({
  windowMs: 60 * 60 * 1000, // 1 hour
  maxRequests: 120,
  message: 'Too many verification attempts. Please try again later.',
});
