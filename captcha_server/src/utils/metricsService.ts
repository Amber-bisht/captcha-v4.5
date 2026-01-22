/**
 * CAPTCHA Metrics Service
 * Tracks success/fail rates, timing, and security events in Redis
 */

import { redis } from '../config/redis';

// Metric keys
const METRICS_PREFIX = 'captcha:metrics:';
const METRICS = {
    // Basic counters
    challengeSuccess: `${METRICS_PREFIX}challenge:success`,
    challengeFail: `${METRICS_PREFIX}challenge:fail`,
    challengeTotal: `${METRICS_PREFIX}challenge:total`,

    verifySuccess: `${METRICS_PREFIX}verify:success`,
    verifyFail: `${METRICS_PREFIX}verify:fail`,
    verifyTotal: `${METRICS_PREFIX}verify:total`,

    // Security events
    replays: `${METRICS_PREFIX}security:replays`,
    timingAttacks: `${METRICS_PREFIX}security:timing_attacks`,

    // Fingerprint tracking (Set)
    dailyFingerprints: (date: string) => `${METRICS_PREFIX}fingerprints:${date}`,

    // Timing histograms
    solveTimeSum: `${METRICS_PREFIX}solve_time:sum`,
    solveTimeCount: `${METRICS_PREFIX}solve_time:count`,
};

// TTL for daily sets (keep 30 days)
const DAILY_TTL = 30 * 24 * 60 * 60;

export class MetricsService {
    /**
     * Record verification result
     */
    static async recordVerification(
        success: boolean,
        solveTimeMs?: number,
        fingerprint?: string
    ): Promise<void> {
        if (success) {
            await Promise.all([
                redis.incr(METRICS.verifySuccess),
                redis.incr(METRICS.verifyTotal),
            ]);
        } else {
            await Promise.all([
                redis.incr(METRICS.verifyFail),
                redis.incr(METRICS.verifyTotal),
            ]);
        }

        // Record solve time
        if (solveTimeMs && success) {
            await Promise.all([
                redis.incrbyfloat(METRICS.solveTimeSum, solveTimeMs),
                redis.incr(METRICS.solveTimeCount),
            ]);
        }

        // Track unique fingerprint (M3)
        if (fingerprint) {
            const dateKey = new Date().toISOString().slice(0, 10); // YYYY-MM-DD
            const key = METRICS.dailyFingerprints(dateKey);
            await redis.sadd(key, fingerprint);
            await redis.expire(key, DAILY_TTL);
        }
    }

    /**
     * Record security events
     */
    static async recordSecurityEvent(
        event: 'replay' | 'timing_attack'
    ): Promise<void> {
        const key = {
            replay: METRICS.replays,
            timing_attack: METRICS.timingAttacks,
        }[event];

        await redis.incr(key);
    }

    /**
     * Get current metrics snapshot
     */
    static async getMetrics(): Promise<any> {
        const [
            verifySuccess,
            verifyFail,
            replays,
            timingAttacks,
            solveTimeSum,
            solveTimeCount,
            bannedDevicesCount,
        ] = await Promise.all([
            redis.get(METRICS.verifySuccess),
            redis.get(METRICS.verifyFail),
            redis.get(METRICS.replays),
            redis.get(METRICS.timingAttacks),
            redis.get(METRICS.solveTimeSum),
            redis.get(METRICS.solveTimeCount),
            redis.scard('banned_devices'),  // Count of banned devices
        ]);

        // Get unique fingerprints count for today
        const dateKey = new Date().toISOString().slice(0, 10);
        const uniqueFingerprints = await redis.scard(METRICS.dailyFingerprints(dateKey));

        const avgSolveTime = parseFloat(solveTimeCount || '0') > 0
            ? parseFloat(solveTimeSum || '0') / parseFloat(solveTimeCount || '1')
            : 0;

        return {
            verifications: {
                success: parseInt(verifySuccess || '0'),
                fail: parseInt(verifyFail || '0'),
            },
            security: {
                replays: parseInt(replays || '0'),
                timingAttacks: parseInt(timingAttacks || '0'),
                uniqueDailyFingerprints: uniqueFingerprints,
                bannedAttempts: bannedDevicesCount || 0,
            },
            performance: {
                avgSolveTimeMs: Math.round(avgSolveTime),
            },
        };
    }
    /**
     * Get hourly statistics (placeholder for now to fix build)
     */
    static async getHourlyStats(hours: number): Promise<any[]> {
        // Return empty array for now, or implement logic if needed.
        // To strictly match expected return type in server.ts
        return [];
    }
}

export default MetricsService;
