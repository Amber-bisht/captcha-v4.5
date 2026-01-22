/**
 * Session Manager - Enforces stage binding across captcha flow
 * Prevents: token harvesting, stage skipping, session hijacking
 * 
 * NOW USES REDIS for persistence and horizontal scaling
 */

import crypto from 'crypto';
import { setWithTTL, getJSON, del, KEYS } from '../config/redis';

export interface CaptchaSession {
    sessionId: string;
    fingerprint: string;
    ip: string;
    createdAt: number;
    expiresAt: number;
    stage: 'init' | 'pow_solved' | 'challenge_issued' | 'verified';
    powNonce?: string;
    powSolvedAt?: number;
    challengeId?: string;
    challengeIssuedAt?: number;
    verifiedAt?: number;
    requestCount: number;
    lastRequestAt: number;
}

interface SessionConfig {
    sessionTtlMs: number;        // Session lifetime
    powValidityMs: number;       // How long PoW solution is valid
    challengeValidityMs: number; // How long before challenge expires
    maxRequestsPerSession: number;
    minTimeBetweenStagesMs: number;
}

const DEFAULT_CONFIG: SessionConfig = {
    sessionTtlMs: 5 * 60 * 1000,      // 5 minutes total session
    powValidityMs: 60 * 1000,          // 60 seconds to submit challenge after PoW
    challengeValidityMs: 90 * 1000,    // 90 seconds to solve challenge
    maxRequestsPerSession: 20,
    minTimeBetweenStagesMs: 500,       // Min 500ms between stages (bot protection)
};

export class SessionManager {
    private config: SessionConfig;

    constructor(config: Partial<SessionConfig> = {}) {
        this.config = { ...DEFAULT_CONFIG, ...config };
    }

    /**
     * Create a new session at init stage
     */
    async createSession(fingerprint: string, ip: string): Promise<CaptchaSession> {
        const sessionId = crypto.randomBytes(32).toString('hex');
        const now = Date.now();

        const session: CaptchaSession = {
            sessionId,
            fingerprint,
            ip,
            createdAt: now,
            expiresAt: now + this.config.sessionTtlMs,
            stage: 'init',
            requestCount: 1,
            lastRequestAt: now,
        };

        // Store in Redis with TTL
        const ttlSeconds = Math.ceil(this.config.sessionTtlMs / 1000);
        await setWithTTL(KEYS.session(sessionId), session, ttlSeconds);

        return session;
    }

    /**
     * Get session by ID
     */
    async getSession(sessionId: string): Promise<CaptchaSession | null> {
        const session = await getJSON<CaptchaSession>(KEYS.session(sessionId));
        if (!session) return null;

        // Check expiration (Redis TTL handles this, but double-check)
        if (Date.now() > session.expiresAt) {
            await del(KEYS.session(sessionId));
            return null;
        }

        return session;
    }

    /**
     * Validate session for a specific stage transition
     */
    async validateTransition(
        sessionId: string,
        fingerprint: string,
        ip: string,
        requiredStage: CaptchaSession['stage'],
        nextStage: CaptchaSession['stage']
    ): Promise<{ valid: boolean; error?: string; session?: CaptchaSession }> {
        const session = await this.getSession(sessionId);

        if (!session) {
            return { valid: false, error: 'Session not found or expired' };
        }

        // Check fingerprint binding
        if (session.fingerprint !== fingerprint) {
            this.recordSuspiciousActivity(session, 'fingerprint_mismatch');
            return { valid: false, error: 'Session fingerprint mismatch' };
        }

        // Check IP binding
        if (session.ip !== ip) {
            this.recordSuspiciousActivity(session, 'ip_changed');
            return { valid: false, error: 'Session IP changed' };
        }

        // Check stage progression
        if (session.stage !== requiredStage) {
            this.recordSuspiciousActivity(session, 'stage_skip_attempt');
            return {
                valid: false,
                error: `Invalid stage transition: expected ${requiredStage}, got ${session.stage}`
            };
        }

        // Check timing between stages (anti-bot)
        const now = Date.now();
        if (now - session.lastRequestAt < this.config.minTimeBetweenStagesMs) {
            return {
                valid: false,
                error: 'Request too fast, please wait'
            };
        }

        // Check request count
        if (session.requestCount >= this.config.maxRequestsPerSession) {
            return { valid: false, error: 'Session request limit exceeded' };
        }

        // Validate stage-specific timing
        if (requiredStage === 'pow_solved' && session.powSolvedAt) {
            if (now - session.powSolvedAt > this.config.powValidityMs) {
                return { valid: false, error: 'PoW solution expired' };
            }
        }

        if (requiredStage === 'challenge_issued' && session.challengeIssuedAt) {
            if (now - session.challengeIssuedAt > this.config.challengeValidityMs) {
                return { valid: false, error: 'Challenge expired' };
            }
        }

        // Update session
        session.stage = nextStage;
        session.requestCount++;
        session.lastRequestAt = now;

        if (nextStage === 'pow_solved') {
            session.powSolvedAt = now;
        } else if (nextStage === 'challenge_issued') {
            session.challengeIssuedAt = now;
        } else if (nextStage === 'verified') {
            session.verifiedAt = now;
        }

        // Calculate remaining TTL
        const remainingTtl = Math.ceil((session.expiresAt - now) / 1000);
        if (remainingTtl > 0) {
            await setWithTTL(KEYS.session(sessionId), session, remainingTtl);
        }

        return { valid: true, session };
    }

    /**
     * Record PoW nonce association with session
     */
    async associatePowNonce(sessionId: string, powNonce: string): Promise<boolean> {
        const session = await this.getSession(sessionId);
        if (!session) return false;

        session.powNonce = powNonce;
        const remainingTtl = Math.ceil((session.expiresAt - Date.now()) / 1000);
        if (remainingTtl > 0) {
            await setWithTTL(KEYS.session(sessionId), session, remainingTtl);
        }
        return true;
    }

    /**
     * Verify PoW nonce belongs to session
     */
    async verifyPowNonce(sessionId: string, powNonce: string): Promise<boolean> {
        const session = await this.getSession(sessionId);
        if (!session) return false;
        return session.powNonce === powNonce;
    }

    /**
     * Associate challenge with session
     */
    async associateChallenge(sessionId: string, challengeId: string): Promise<boolean> {
        const session = await this.getSession(sessionId);
        if (!session) return false;

        session.challengeId = challengeId;
        const remainingTtl = Math.ceil((session.expiresAt - Date.now()) / 1000);
        if (remainingTtl > 0) {
            await setWithTTL(KEYS.session(sessionId), session, remainingTtl);
        }
        return true;
    }

    /**
     * Verify challenge belongs to session
     */
    async verifyChallengeId(sessionId: string, challengeId: string): Promise<boolean> {
        const session = await this.getSession(sessionId);
        if (!session) return false;
        return session.challengeId === challengeId;
    }

    /**
     * Invalidate session after successful verification
     */
    async invalidateSession(sessionId: string): Promise<void> {
        await del(KEYS.session(sessionId));
    }

    /**
     * Record suspicious activity on session
     */
    private recordSuspiciousActivity(session: CaptchaSession, type: string): void {
        console.warn(`[SESSION] Suspicious activity: ${type}`, {
            sessionId: session.sessionId.substring(0, 8),
            fingerprint: session.fingerprint.substring(0, 8),
            ip: session.ip,
        });
    }
}

// Singleton instance
export const sessionManager = new SessionManager();
