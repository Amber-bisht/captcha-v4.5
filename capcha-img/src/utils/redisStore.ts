/**
 * Redis-based Storage Service
 * Replaces all in-memory Maps/Sets with Redis storage
 */

import redisClient, { REDIS_KEYS, TTL } from '../config/redis';
import { SecureImage, SecureChallenge } from './secureImageServer';

// Interface for stored challenge data
interface StoredChallenge {
    challenge?: any;        // For image challenges
    textAnswer?: string;    // For dynamic text challenges
    type: 'image' | 'text'; // Type of challenge
    fingerprint: string;
    ip: string;
    expiresAt: number;
}

// Interface for image mapping
interface ImageMapping {
    file: string;
    category: string;
    sessionId: string;
}

/**
 * RedisStore - Centralized Redis operations for CAPTCHA
 */
export class RedisStore {
    // ==========================================
    // CHALLENGE STORAGE
    // ==========================================

    /**
     * Store a challenge
     */
    static async setChallenge(sessionId: string, data: StoredChallenge): Promise<void> {
        const key = REDIS_KEYS.CHALLENGE + sessionId;
        await redisClient.setex(key, TTL.CHALLENGE, JSON.stringify(data));
    }

    /**
     * Get a challenge
     */
    static async getChallenge(sessionId: string): Promise<StoredChallenge | null> {
        const key = REDIS_KEYS.CHALLENGE + sessionId;
        const data = await redisClient.get(key);
        return data ? JSON.parse(data) : null;
    }

    /**
     * Delete a challenge
     */
    static async deleteChallenge(sessionId: string): Promise<void> {
        const key = REDIS_KEYS.CHALLENGE + sessionId;
        await redisClient.del(key);
    }

    // ==========================================
    // SESSION IMAGES STORAGE
    // ==========================================

    /**
     * Store session images with target category
     */
    static async setSessionImages(
        sessionId: string,
        images: Map<string, SecureImage>,
        targetCategory: string
    ): Promise<void> {
        const key = REDIS_KEYS.SESSION_IMAGES + sessionId;
        const data = {
            images: Object.fromEntries(images),
            targetCategory,
        };
        await redisClient.setex(key, TTL.SESSION, JSON.stringify(data));
    }

    /**
     * Get session images and target category
     */
    static async getSessionImages(sessionId: string): Promise<{
        images: Map<string, SecureImage>;
        targetCategory: string;
    } | null> {
        const key = REDIS_KEYS.SESSION_IMAGES + sessionId;
        const data = await redisClient.get(key);
        if (!data) return null;

        const parsed = JSON.parse(data);
        return {
            images: new Map(Object.entries(parsed.images)),
            targetCategory: parsed.targetCategory,
        };
    }

    /**
     * Delete session images
     */
    static async deleteSessionImages(sessionId: string): Promise<void> {
        const key = REDIS_KEYS.SESSION_IMAGES + sessionId;
        await redisClient.del(key);
    }

    // ==========================================
    // IMAGE ID MAPPING
    // ==========================================

    /**
     * Store image ID to file mapping
     */
    static async setImageMapping(imageId: string, mapping: ImageMapping): Promise<void> {
        const key = REDIS_KEYS.IMAGE_MAPPING + imageId;
        await redisClient.setex(key, TTL.SESSION, JSON.stringify(mapping));
    }

    /**
     * Get image mapping
     */
    static async getImageMapping(imageId: string): Promise<ImageMapping | null> {
        const key = REDIS_KEYS.IMAGE_MAPPING + imageId;
        const data = await redisClient.get(key);
        return data ? JSON.parse(data) : null;
    }

    /**
     * Delete image mapping
     */
    static async deleteImageMapping(imageId: string): Promise<void> {
        const key = REDIS_KEYS.IMAGE_MAPPING + imageId;
        await redisClient.del(key);
    }

    /**
     * Batch delete image mappings for a session
     */
    static async deleteImageMappingsBatch(imageIds: string[]): Promise<void> {
        if (imageIds.length === 0) return;
        const keys = imageIds.map(id => REDIS_KEYS.IMAGE_MAPPING + id);
        await redisClient.del(...keys);
    }

    // ==========================================
    // USED TOKENS (Prevent Replay)
    // ==========================================

    /**
     * Mark a success token as used
     */
    static async markTokenUsed(token: string): Promise<void> {
        const key = REDIS_KEYS.USED_TOKEN + token;
        await redisClient.setex(key, TTL.TOKEN, '1');
    }

    /**
     * Check if token has been used
     */
    static async isTokenUsed(token: string): Promise<boolean> {
        const key = REDIS_KEYS.USED_TOKEN + token;
        const exists = await redisClient.exists(key);
        return exists === 1;
    }

    // ==========================================
    // USED NONCES (Prevent Token Replay)
    // ==========================================

    /**
     * Mark a nonce as used
     */
    static async markNonceUsed(nonce: string): Promise<void> {
        const key = REDIS_KEYS.USED_NONCE + nonce;
        await redisClient.setex(key, TTL.TOKEN, '1');
    }

    /**
     * Check if nonce has been used
     */
    static async isNonceUsed(nonce: string): Promise<boolean> {
        const key = REDIS_KEYS.USED_NONCE + nonce;
        const exists = await redisClient.exists(key);
        return exists === 1;
    }

    // ==========================================
    // RATE LIMITING
    // ==========================================

    /**
     * Increment rate limit counter
     * Returns current count
     */
    static async incrementRateLimit(identifier: string, windowMs: number): Promise<number> {
        const key = REDIS_KEYS.RATE_LIMIT + identifier;
        const multi = redisClient.multi();

        multi.incr(key);
        multi.pexpire(key, windowMs);

        const results = await multi.exec();
        return results ? (results[0][1] as number) : 0;
    }

    /**
     * Get current rate limit count
     */
    static async getRateLimitCount(identifier: string): Promise<number> {
        const key = REDIS_KEYS.RATE_LIMIT + identifier;
        const count = await redisClient.get(key);
        return count ? parseInt(count, 10) : 0;
    }

    // ==========================================
    // FINGERPRINT STORAGE (Server-side only)
    // ==========================================

    /**
     * Store server-generated fingerprint for a session
     * This replaces client-provided fingerprint for security
     */
    static async setServerFingerprint(sessionId: string, fingerprint: string): Promise<void> {
        const key = `captcha:fingerprint:${sessionId}`;
        await redisClient.setex(key, TTL.SESSION, fingerprint);
    }

    /**
     * Get server-generated fingerprint
     */
    static async getServerFingerprint(sessionId: string): Promise<string | null> {
        const key = `captcha:fingerprint:${sessionId}`;
        return await redisClient.get(key);
    }
}

export default RedisStore;
