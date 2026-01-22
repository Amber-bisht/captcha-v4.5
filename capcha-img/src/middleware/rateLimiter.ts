import rateLimit, { RateLimitRequestHandler } from 'express-rate-limit';
import { Request, Response, NextFunction } from 'express';
import { RateLimitConfig } from '../types/rateLimit';
import redisClient from '../config/redis';
import RateLimitConfigModel from '../models/RateLimitConfig';

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
export function createRateLimiter(config: RateLimitConfig, prefix: string = 'captcha:ratelimit') {
  const store = new RedisRateLimitStore(config.windowMs, prefix);

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

// Manager to hold dynamic instances
class RateLimitManager {
  private limiters: Map<string, RateLimitRequestHandler> = new Map();

  async init() {
    console.log('🔄 Initializing Rate Limiters...');
    await this.loadOrCreateInfo('request-challenge', 60 * 60 * 1000, 10, 'Too many challenge requests.');
    await this.loadOrCreateInfo('verify', 60 * 60 * 1000, 60, 'Too many verification attempts.');
    console.log('✅ Rate Limiters Initialized');
  }

  async loadOrCreateInfo(endpoint: string, defaultWindow: number, defaultMax: number, defaultMsg: string) {
    let config = await RateLimitConfigModel.findOne({ endpoint });

    if (!config) {
      console.log(`Creating default rate limit for ${endpoint}`);
      config = await RateLimitConfigModel.create({
        endpoint,
        windowMs: defaultWindow,
        maxRequests: defaultMax,
        message: defaultMsg,
        isActive: true
      });
    }

    const limiter = createRateLimiter({
      windowMs: config.windowMs,
      maxRequests: config.maxRequests,
      message: config.message
    }, `captcha:ratelimit:${endpoint}`);

    this.limiters.set(endpoint, limiter);
  }

  async reload(endpoint: string) {
    const config = await RateLimitConfigModel.findOne({ endpoint });
    if (config) {
      const limiter = createRateLimiter({
        windowMs: config.windowMs,
        maxRequests: config.maxRequests,
        message: config.message
      }, `captcha:ratelimit:${endpoint}`); // Use distinct prefix per endpoint
      this.limiters.set(endpoint, limiter);
      return config;
    }
    return null;
  }

  getMiddleware(endpoint: string) {
    return (req: Request, res: Response, next: NextFunction) => {
      const limiter = this.limiters.get(endpoint);
      if (limiter) {
        limiter(req, res, next);
      } else {
        // Fallback or error if not initialized
        console.error(`Rate limiter for ${endpoint} not initialized!`);
        next();
      }
    };
  }
}

export const rateLimitManager = new RateLimitManager();

/**
 * Challenge rate limiter: Dynamic
 */
export const challengeRateLimiter = rateLimitManager.getMiddleware('request-challenge');

/**
 * Verification rate limiter: Dynamic
 */
export const verificationRateLimiter = rateLimitManager.getMiddleware('verify');


