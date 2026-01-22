import rateLimit from 'express-rate-limit';
import { Request, Response } from 'express';
import { RateLimitConfig } from '../types/rateLimit';
import redisClient from '../config/redis';

/**
 * SECURITY FIX P1.3: Redis-based rate limit store for express-rate-limit
 * Enables horizontal scaling - rate limits are shared across all server instances
 */
class RedisRateLimitStore {
  windowMs: number;
  prefix: string;

  constructor(windowMs: number, prefix: string = 'captcha:ratelimit') {
    this.windowMs = windowMs;
    this.prefix = prefix;
  }

  private getKey(key: string): string {
    return `${this.prefix}:${key}`;
  }

  /**
   * Increment the counter for a key
   */
  async increment(key: string): Promise<{ totalHits: number; resetTime: Date }> {
    const redisKey = this.getKey(key);
    const now = Date.now();
    const resetTime = new Date(now + this.windowMs);

    // Use Redis INCR with PEXPIRE for atomic increment + TTL
    const multi = redisClient.multi();
    multi.incr(redisKey);
    multi.pexpire(redisKey, this.windowMs);
    const results = await multi.exec();

    const totalHits = results?.[0]?.[1] as number || 1;

    return { totalHits, resetTime };
  }

  async decrement(key: string): Promise<void> {
    const redisKey = this.getKey(key);
    await redisClient.decr(redisKey);
  }

  async resetKey(key: string): Promise<void> {
    await redisClient.del(this.getKey(key));
  }
}

/**
 * Create a rate limiter middleware with Redis store
 */
export function createRateLimiter(config: RateLimitConfig) {
  const store = new RedisRateLimitStore(config.windowMs, 'captcha:ratelimit');

  return rateLimit({
    windowMs: config.windowMs,
    max: config.maxRequests,
    message: config.message || 'Too many requests, please try again later.',
    standardHeaders: config.standardHeaders ?? true,
    legacyHeaders: config.legacyHeaders ?? true,
    store: store as any, // Type assertion for express-rate-limit compatibility
    // Custom key generator combining IP + fingerprint
    keyGenerator: (req: Request): string => {
      const ip = req.ip || req.socket.remoteAddress || 'unknown';
      const fingerprint = req.fingerprint?.hash || '';
      return `${ip}:${fingerprint}`;
    },
    // Custom handler with structured response
    handler: (req: Request, res: Response) => {
      res.status(429).json({
        success: false,
        message: config.message || 'Too many requests, please try again later.',
        retryAfter: Math.ceil(config.windowMs / 1000),
      });
    },
  });
}

/**
 * Challenge rate limiter: 10 requests per hour
 * SECURITY FIX M1: Reduced from 20 to 10 to resist distributed attacks
 */
export const challengeRateLimiter = createRateLimiter({
  windowMs: 60 * 60 * 1000, // 1 hour
  maxRequests: 10,
  message: 'Too many challenge requests. Please try again later.',
});

/**
 * Verification rate limiter: 60 requests per hour (1 per minute)
 * SECURITY FIX M1: Reduced from 120 to 60
 */
export const verificationRateLimiter = createRateLimiter({
  windowMs: 60 * 60 * 1000, // 1 hour
  maxRequests: 60,
  message: 'Too many verification attempts. Please try again later.',
});


