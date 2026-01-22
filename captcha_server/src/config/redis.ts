/**
 * Redis Service - Centralized Redis connection management
 * 
 * Provides connection pooling, automatic reconnection, and typed helpers
 * for common patterns used throughout the captcha server.
 */

import Redis from 'ioredis';

// Redis configuration from environment
const REDIS_URL = process.env.REDIS_URL || 'redis://localhost:6379';

// Create Redis client
const redis = new Redis(REDIS_URL, {
    maxRetriesPerRequest: 3,
    retryStrategy(times) {
        const delay = Math.min(times * 50, 2000);
        console.log(`[REDIS] Reconnecting in ${delay}ms (attempt ${times})`);
        return delay;
    },
    reconnectOnError(err) {
        const targetErrors = ['READONLY', 'ECONNRESET', 'ECONNREFUSED'];
        return targetErrors.some(e => err.message.includes(e));
    },
});

// Event handlers
redis.on('connect', () => {
    console.log('[REDIS] Connected to Redis server');
});

redis.on('error', (err) => {
    console.error('[REDIS] Connection error:', err.message);
});

redis.on('close', () => {
    console.log('[REDIS] Connection closed');
});

// ============================================
// HELPER FUNCTIONS
// ============================================

/**
 * Set a value with expiration (in seconds)
 */
export async function setWithTTL(key: string, value: string | object, ttlSeconds: number): Promise<void> {
    const stringValue = typeof value === 'string' ? value : JSON.stringify(value);
    await redis.setex(key, ttlSeconds, stringValue);
}

/**
 * Get a value and parse as JSON if possible
 */
export async function getJSON<T>(key: string): Promise<T | null> {
    const value = await redis.get(key);
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
    await redis.del(key);
}

/**
 * Check if key exists
 */
export async function exists(key: string): Promise<boolean> {
    return (await redis.exists(key)) === 1;
}

/**
 * Increment a counter with expiration
 */
export async function incrementWithTTL(key: string, ttlSeconds: number): Promise<number> {
    const multi = redis.multi();
    multi.incr(key);
    multi.expire(key, ttlSeconds);
    const results = await multi.exec();
    return results?.[0]?.[1] as number || 0;
}

/**
 * Get remaining TTL for a key
 */
export async function getTTL(key: string): Promise<number> {
    return await redis.ttl(key);
}

/**
 * Store a hash (object with multiple fields)
 */
export async function setHash(key: string, data: Record<string, string | number>, ttlSeconds?: number): Promise<void> {
    const stringData: Record<string, string> = {};
    for (const [k, v] of Object.entries(data)) {
        stringData[k] = String(v);
    }
    await redis.hset(key, stringData);
    if (ttlSeconds) {
        await redis.expire(key, ttlSeconds);
    }
}

/**
 * Get all fields from a hash
 */
export async function getHash(key: string): Promise<Record<string, string> | null> {
    const data = await redis.hgetall(key);
    return Object.keys(data).length > 0 ? data : null;
}

/**
 * Update specific field in a hash
 */
export async function updateHashField(key: string, field: string, value: string | number): Promise<void> {
    await redis.hset(key, field, String(value));
}

/**
 * Add to a set (for unique tracking like used nonces)
 */
export async function addToSet(key: string, value: string, ttlSeconds?: number): Promise<void> {
    await redis.sadd(key, value);
    if (ttlSeconds) {
        await redis.expire(key, ttlSeconds);
    }
}

/**
 * Check if value exists in set
 */
export async function isInSet(key: string, value: string): Promise<boolean> {
    return (await redis.sismember(key, value)) === 1;
}

/**
 * Push to a list with max length limit
 */
export async function pushToList(key: string, value: string, maxLength: number, ttlSeconds?: number): Promise<void> {
    await redis.lpush(key, value);
    await redis.ltrim(key, 0, maxLength - 1);
    if (ttlSeconds) {
        await redis.expire(key, ttlSeconds);
    }
}

/**
 * Get list values
 */
export async function getList(key: string, start = 0, end = -1): Promise<string[]> {
    return await redis.lrange(key, start, end);
}

// ============================================
// KEY PATTERNS
// ============================================
export const KEYS = {
    session: (id: string) => `session:${id}`,
    challenge: (id: string) => `challenge:${id}`,
    device: (fingerprint: string) => `device:${fingerprint}`,
    pow: (id: string) => `pow:${id}`,
    rateLimit: (ip: string, endpoint: string) => `ratelimit:${ip}:${endpoint}`,
    usedNonce: (nonce: string) => `nonce:${nonce}`,
    velocity: (fingerprint: string) => `velocity:${fingerprint}`,
};

// ============================================
// GRACEFUL SHUTDOWN
// ============================================
export async function closeRedis(): Promise<void> {
    console.log('[REDIS] Closing connection...');
    await redis.quit();
}

// Handle process termination
process.on('SIGINT', async () => {
    await closeRedis();
    process.exit(0);
});

process.on('SIGTERM', async () => {
    await closeRedis();
    process.exit(0);
});

// Export the raw client for advanced usage
export { redis };
export default redis;
