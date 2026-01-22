import rateLimit from 'express-rate-limit';
import { Request, Response } from 'express';
import { RateLimitConfig } from '../types/rateLimit';
import { redis } from '../config/redis';

/**
 * Redis-based rate limit store for express-rate-limit
 */
class RedisRateLimitStore {
  windowMs: number;
  prefix: string;

  constructor(windowMs: number, prefix: string = 'ratelimit') {
    this.windowMs = windowMs;
    this.prefix = prefix;
  }

  /**
   * Get the key for a client
   */
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

    // Use Redis INCR with EXPIRE
    const multi = redis.multi();
    multi.incr(redisKey);
    multi.pexpire(redisKey, this.windowMs);
    const results = await multi.exec();

    const totalHits = results?.[0]?.[1] as number || 1;

    return { totalHits, resetTime };
  }

  /**
   * Decrement the counter
   */
  async decrement(key: string): Promise<void> {
    const redisKey = this.getKey(key);
    await redis.decr(redisKey);
  }

  /**
   * Reset a key
   */
  async resetKey(key: string): Promise<void> {
    await redis.del(this.getKey(key));
  }
}

/**
 * Create a rate limiter middleware with Redis store
 */
export function createRateLimiter(config: RateLimitConfig) {
  const store = new RedisRateLimitStore(config.windowMs, 'ratelimit');

  return rateLimit({
    windowMs: config.windowMs,
    max: config.maxRequests,
    message: config.message || 'Too many requests, please try again later.',
    standardHeaders: config.standardHeaders ?? true,
    legacyHeaders: config.legacyHeaders ?? false,
    store: store as any, // Type assertion for express-rate-limit compatibility
    // Custom key generator
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
 * Challenge rate limiter: 60 requests per hour
 */
export const challengeRateLimiter = createRateLimiter({
  windowMs: 60 * 60 * 1000, // 1 hour
  maxRequests: 60,
  message: 'Too many challenge requests. Please try again later.',
});

/**
 * Verification rate limiter: 120 requests per hour
 */
export const verificationRateLimiter = createRateLimiter({
  windowMs: 60 * 60 * 1000, // 1 hour
  maxRequests: 120,
  message: 'Too many verification attempts. Please try again later.',
});
