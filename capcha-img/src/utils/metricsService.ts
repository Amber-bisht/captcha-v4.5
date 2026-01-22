/**
 * CAPTCHA Metrics Service
 * Tracks success/fail rates, timing, and security events in Redis
 * V2: Added fingerprint entropy tracking (M3)
 */

import redisClient, { REDIS_KEYS } from '../config/redis';

// Metric keys
const METRICS_PREFIX = 'captcha:metrics:';
const METRICS = {
    challengeSuccess: `${METRICS_PREFIX}challenge:success`,
    challengeFail: `${METRICS_PREFIX}challenge:fail`,
    challengeTotal: `${METRICS_PREFIX}challenge:total`,

    verifySuccess: `${METRICS_PREFIX}verify:success`,
    verifyFail: `${METRICS_PREFIX}verify:fail`,
    verifyTotal: `${METRICS_PREFIX}verify:total`,

    bannedAttempts: `${METRICS_PREFIX}banned_attempts`,
    honeypotTriggered: `${METRICS_PREFIX}honeypot`,
    fingerprintAnomalies: `${METRICS_PREFIX}fingerprint_anomaly`,
    replays: `${METRICS_PREFIX}security:replays`,
    timingAttacks: `${METRICS_PREFIX}security:timing_attacks`,

    // Time-series buckets (hourly)
    hourlySuccess: (hour: string) => `${METRICS_PREFIX}hourly:success:${hour}`,
    hourlyFail: (hour: string) => `${METRICS_PREFIX}hourly:fail:${hour}`,

    // By type
    spatialSuccess: `${METRICS_PREFIX}spatial:success`,
    spatialFail: `${METRICS_PREFIX}spatial:fail`,
    textSuccess: `${METRICS_PREFIX}text:success`,
    textFail: `${METRICS_PREFIX}text:fail`,

    // Timing histograms
    solveTimeSum: `${METRICS_PREFIX}solve_time:sum`,
    solveTimeCount: `${METRICS_PREFIX}solve_time:count`,

    // Fingerprints (M3)
    dailyFingerprints: (date: string) => `${METRICS_PREFIX}fingerprints:${date}`,
};

// TTL for hourly buckets (keep 7 days)
const HOURLY_TTL = 7 * 24 * 60 * 60;
// TTL for daily sets (keep 30 days)
const DAILY_TTL = 30 * 24 * 60 * 60;

export class MetricsService {
    /**
     * Record a challenge request
     */
    static async recordChallengeRequest(type: 'spatial' | 'text'): Promise<void> {
        await redisClient.incr(METRICS.challengeTotal);
    }

    /**
     * Record verification result
     */
    static async recordVerification(
        success: boolean,
        type: 'spatial' | 'text',
        solveTimeMs?: number,
        fingerprint?: string
    ): Promise<void> {
        const hourKey = new Date().toISOString().slice(0, 13); // YYYY-MM-DDTHH

        if (success) {
            await Promise.all([
                redisClient.incr(METRICS.verifySuccess),
                redisClient.incr(METRICS.verifyTotal),
                redisClient.incr(METRICS.hourlySuccess(hourKey)),
                redisClient.incr(type === 'spatial' ? METRICS.spatialSuccess : METRICS.textSuccess),
            ]);

            // Set TTL on hourly bucket
            await redisClient.expire(METRICS.hourlySuccess(hourKey), HOURLY_TTL);
        } else {
            await Promise.all([
                redisClient.incr(METRICS.verifyFail),
                redisClient.incr(METRICS.verifyTotal),
                redisClient.incr(METRICS.hourlyFail(hourKey)),
                redisClient.incr(type === 'spatial' ? METRICS.spatialFail : METRICS.textFail),
            ]);

            await redisClient.expire(METRICS.hourlyFail(hourKey), HOURLY_TTL);
        }

        // Record solve time
        if (solveTimeMs && success) {
            await Promise.all([
                redisClient.incrbyfloat(METRICS.solveTimeSum, solveTimeMs),
                redisClient.incr(METRICS.solveTimeCount),
            ]);
        }

        // Track unique fingerprint (M3)
        if (fingerprint) {
            const dateKey = new Date().toISOString().slice(0, 10); // YYYY-MM-DD
            const key = METRICS.dailyFingerprints(dateKey);
            await redisClient.sadd(key, fingerprint);
            await redisClient.expire(key, DAILY_TTL);
        }
    }

    /**
     * Record security events
     */
    static async recordSecurityEvent(
        event: 'banned_attempt' | 'honeypot' | 'fingerprint_anomaly'
    ): Promise<void> {
        const key = {
            banned_attempt: METRICS.bannedAttempts,
            honeypot: METRICS.honeypotTriggered,
            fingerprint_anomaly: METRICS.fingerprintAnomalies,
        }[event];

        await redisClient.incr(key);
    }

    /**
     * Get current metrics snapshot
     */
    static async getMetrics(): Promise<any> {
        const [
            challengeTotal,
            verifySuccess,
            verifyFail,
            spatialSuccess,
            spatialFail,
            textSuccess,
            textFail,
            bannedAttempts,
            honeypotTriggered,
            fingerprintAnomalies,
            solveTimeSum,
            solveTimeCount,
            replays,
            timingAttacks
        ] = await Promise.all([
            redisClient.get(METRICS.challengeTotal),
            redisClient.get(METRICS.verifySuccess),
            redisClient.get(METRICS.verifyFail),
            redisClient.get(METRICS.spatialSuccess),
            redisClient.get(METRICS.spatialFail),
            redisClient.get(METRICS.textSuccess),
            redisClient.get(METRICS.textFail),
            redisClient.get(METRICS.bannedAttempts),
            redisClient.get(METRICS.honeypotTriggered),
            redisClient.get(METRICS.fingerprintAnomalies),
            redisClient.get(METRICS.solveTimeSum),
            redisClient.get(METRICS.solveTimeCount),
            redisClient.get(METRICS.replays),
            redisClient.get(METRICS.timingAttacks),
        ]);

        // Get unique fingerprints count for today
        const dateKey = new Date().toISOString().slice(0, 10);
        const uniqueFingerprints = await redisClient.scard(METRICS.dailyFingerprints(dateKey));

        const totalSuccess = parseInt(verifySuccess || '0');
        const verificationCount = totalSuccess + parseInt(verifyFail || '0');
        const avgSolveTime = parseFloat(solveTimeCount || '0') > 0
            ? parseFloat(solveTimeSum || '0') / parseFloat(solveTimeCount || '1')
            : 0;

        return {
            totals: {
                challenges: parseInt(challengeTotal || '0'),
                verifications: verificationCount,
                successRate: verificationCount > 0 ? Math.round((totalSuccess / verificationCount) * 100) : 0,
            },
            byType: {
                spatial: {
                    success: parseInt(spatialSuccess || '0'),
                    fail: parseInt(spatialFail || '0'),
                },
                text: {
                    success: parseInt(textSuccess || '0'),
                    fail: parseInt(textFail || '0'),
                },
            },
            security: {
                bannedAttempts: parseInt(bannedAttempts || '0'),
                honeypotTriggered: parseInt(honeypotTriggered || '0'),
                fingerprintAnomalies: parseInt(fingerprintAnomalies || '0'),
                uniqueDailyFingerprints: uniqueFingerprints,
                replays: parseInt(replays || '0'),
                timingAttacks: parseInt(timingAttacks || '0')
            },
            performance: {
                avgSolveTimeMs: Math.round(avgSolveTime),
            },
        };
    }

    // ... getHourlyStats omitted for brevity
}

export default MetricsService;
