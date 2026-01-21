/**
 * Redis Configuration and Client
 * Centralized Redis connection for all storage needs
 */

import Redis from 'ioredis';

// Redis connection URL from environment
const REDIS_URL = process.env.REDIS_URL || 'redis://localhost:6379';
const REDIS_PASSWORD = process.env.REDIS_PASSWORD;

// Create Redis client
const redisClient = new Redis(REDIS_URL, {
    password: REDIS_PASSWORD || undefined,
    retryStrategy: (times: number) => {
        // Retry with exponential backoff
        const delay = Math.min(times * 100, 3000);
        return delay;
    },
    maxRetriesPerRequest: 3,
    lazyConnect: true,
});

// Connection event handlers
redisClient.on('connect', () => {
    console.log('✅ Redis connected successfully');
});

redisClient.on('error', (err) => {
    console.error('❌ Redis connection error:', err.message);
});

redisClient.on('reconnecting', () => {
    console.log('🔄 Redis reconnecting...');
});

// Key prefixes for different data types
export const REDIS_KEYS = {
    // Challenge storage (5 min TTL)
    CHALLENGE: 'captcha:challenge:',

    // Session images (5 min TTL)
    SESSION_IMAGES: 'captcha:session:',

    // Image ID to file mapping (5 min TTL)
    IMAGE_MAPPING: 'captcha:image:',

    // Used success tokens (10 min TTL)
    USED_TOKEN: 'captcha:used_token:',

    // Used nonces for replay prevention (10 min TTL)
    USED_NONCE: 'captcha:nonce:',

    // Rate limiting (1 hour TTL)
    RATE_LIMIT: 'captcha:rate:',

    // Device reputation (24 hour TTL)
    DEVICE_REP: 'captcha:device:',
};

// TTL constants in seconds
export const TTL = {
    CHALLENGE: 5 * 60,        // 5 minutes
    SESSION: 5 * 60,          // 5 minutes
    TOKEN: 10 * 60,           // 10 minutes
    RATE_LIMIT: 60 * 60,      // 1 hour
    DEVICE: 24 * 60 * 60,     // 24 hours
};

/**
 * Initialize Redis connection
 */
export async function initRedis(): Promise<boolean> {
    try {
        await redisClient.connect();
        await redisClient.ping();
        console.log('✅ Redis ping successful');
        return true;
    } catch (error) {
        console.error('❌ Failed to connect to Redis:', error);
        return false;
    }
}

/**
 * Check if Redis is connected
 */
export function isRedisConnected(): boolean {
    return redisClient.status === 'ready';
}

export default redisClient;
