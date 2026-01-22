/**
 * PoW Challenge Store - Redis-backed storage for Proof of Work challenges
 */

import { setWithTTL, getJSON, del, KEYS } from '../config/redis';

export interface StoredPoWChallenge {
    id: string;
    prefix: string;
    difficulty: number;
    timestamp: number;
    expiresAt: number;
    algorithm: string;
    createdAt: number;
}

// PoW challenge TTL: 45 seconds (matches config)
const POW_TTL = 45;

export const powChallengeStore = {
    /**
     * Store a new PoW challenge
     */
    async set(id: string, challenge: StoredPoWChallenge): Promise<void> {
        await setWithTTL(KEYS.pow(id), challenge, POW_TTL);
    },

    /**
     * Get a PoW challenge by ID
     */
    async get(id: string): Promise<StoredPoWChallenge | null> {
        return await getJSON<StoredPoWChallenge>(KEYS.pow(id));
    },

    /**
     * Delete a PoW challenge
     */
    async delete(id: string): Promise<void> {
        await del(KEYS.pow(id));
    },
};
