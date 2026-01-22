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
    DEVICE: 7 * 24 * 60 * 60, // 7 days (updated for device profile persistence)
};

// ============================================
// HELPER FUNCTIONS
// ============================================

/**
 * Set a value with expiration (in seconds)
 */
export async function setWithTTL(key: string, value: string | object, ttlSeconds: number): Promise<void> {
    const stringValue = typeof value === 'string' ? value : JSON.stringify(value);
    await redisClient.setex(key, ttlSeconds, stringValue);
}

/**
 * Get a value and parse as JSON if possible
 */
export async function getJSON<T>(key: string): Promise<T | null> {
    const value = await redisClient.get(key);
    if (!value) return null;

    try {
        return JSON.parse(value) as T;
    } catch {
        return value as unknown as T;
    }
}

/**
 * Delete a key
 */
export async function del(key: string): Promise<void> {
    await redisClient.del(key);
}

/**
 * Add to a set (for unique tracking like banned devices)
 */
export async function addToSet(key: string, value: string): Promise<void> {
    await redisClient.sadd(key, value);
}

/**
 * Remove from a set
 */
export async function removeFromSet(key: string, value: string): Promise<void> {
    await redisClient.srem(key, value);
}

/**
 * Check if value exists in set
 */
export async function isInSet(key: string, value: string): Promise<boolean> {
    return (await redisClient.sismember(key, value)) === 1;
}

/**
 * Get set size
 */
export async function getSetSize(key: string): Promise<number> {
    return await redisClient.scard(key);
}

/**
 * Scan keys matching a pattern (use carefully in production)
 */
export async function scanKeys(pattern: string): Promise<string[]> {
    const keys: string[] = [];
    let cursor = '0';

    do {
        const [newCursor, foundKeys] = await redisClient.scan(cursor, 'MATCH', pattern, 'COUNT', 100);
        cursor = newCursor;
        keys.push(...foundKeys);
    } while (cursor !== '0');

    return keys;
}

// ============================================
// KEY PATTERNS
// ============================================
export const KEYS = {
    device: (fingerprintHash: string) => `${REDIS_KEYS.DEVICE_REP}${fingerprintHash}`,
    bannedDevices: () => 'captcha:banned_devices',
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

