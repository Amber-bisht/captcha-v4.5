/**
 * Challenge Store - Redis-backed storage for captcha challenges
 */

import { setWithTTL, getJSON, del, KEYS } from '../config/redis';
import { CaptchaGenerator } from './captchaGenerator';

export interface StoredChallenge {
    challenge: ReturnType<typeof CaptchaGenerator.generateChallenge>;
    fingerprint: string;
    ip: string;
    createdAt: number;
}

// Challenge TTL in seconds (2 minutes)
const CHALLENGE_TTL = 120;

export const challengeStore = {
    /**
     * Store a new challenge
     */
    async set(challengeId: string, data: StoredChallenge): Promise<void> {
        await setWithTTL(KEYS.challenge(challengeId), data, CHALLENGE_TTL);
    },

    /**
     * Get a challenge by ID
     */
    async get(challengeId: string): Promise<StoredChallenge | null> {
        return await getJSON<StoredChallenge>(KEYS.challenge(challengeId));
    },

    /**
     * Delete a challenge
     */
    async delete(challengeId: string): Promise<void> {
        await del(KEYS.challenge(challengeId));
    },

    /**
     * Schedule deletion after a delay
     */
    scheduleDelete(challengeId: string, delayMs: number): void {
        setTimeout(async () => {
            await del(KEYS.challenge(challengeId));
        }, delayMs);
    },
};
