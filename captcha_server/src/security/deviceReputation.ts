/**
 * Device Reputation System
 * Tracks device behavior over time and assigns reputation scores
 * 
 * NOW USES REDIS for persistence and horizontal scaling
 */

import crypto from 'crypto';
import { setWithTTL, getJSON, del, addToSet, isInSet, KEYS } from '../config/redis';

export interface DeviceProfile {
    fingerprintHash: string;
    firstSeen: number;
    lastSeen: number;
    totalRequests: number;
    successfulChallenges: number;
    failedChallenges: number;
    suspiciousActivities: SuspiciousActivity[];
    knownIPs: string[];
    reputationScore: number; // 0-100, higher is better
    isBanned: boolean;
    banReason?: string;
    banExpiry?: number;
    // Velocity tracking (Phase A enhancement)
    requestTimestamps: number[];
    velocityScore: number;
    lastVelocityCheck: number;
}

export interface SuspiciousActivity {
    timestamp: number;
    type: string;
    details: string;
    severity: 'low' | 'medium' | 'high';
}

export interface DeviceReputationResult {
    fingerprintHash: string;
    reputationScore: number;
    reputationLevel: 'trusted' | 'neutral' | 'suspicious' | 'malicious';
    isBanned: boolean;
    banReason?: string;
    challengeMultiplier: number;
    recommendations: string[];
}

// Device profile TTL: 7 days of inactivity
const DEVICE_TTL = 7 * 24 * 60 * 60; // 7 days in seconds
const BAN_SET_KEY = 'banned_devices';

export class DeviceReputationSystem {
    private decayRate: number = 0.99;
    private maxSuspiciousActivities: number = 100;

    /**
     * Get or create a device profile
     */
    async getProfile(fingerprintHash: string): Promise<DeviceProfile> {
        const existing = await getJSON<DeviceProfile>(KEYS.device(fingerprintHash));
        const now = Date.now();

        if (existing) {
            // Update lastSeen and save
            existing.lastSeen = now;
            return existing;
        }

        // Create new profile
        const profile: DeviceProfile = {
            fingerprintHash,
            firstSeen: now,
            lastSeen: now,
            totalRequests: 0,
            successfulChallenges: 0,
            failedChallenges: 0,
            suspiciousActivities: [],
            knownIPs: [],
            reputationScore: 50,
            isBanned: false,
            requestTimestamps: [],
            velocityScore: 0,
            lastVelocityCheck: now,
        };

        await this.saveProfile(profile);
        return profile;
    }

    /**
     * Save profile to Redis
     */
    private async saveProfile(profile: DeviceProfile): Promise<void> {
        await setWithTTL(KEYS.device(profile.fingerprintHash), profile, DEVICE_TTL);
    }

    /**
     * Record request and update velocity
     */
    async recordRequest(fingerprintHash: string): Promise<{ allowed: boolean; velocityScore: number }> {
        const profile = await this.getProfile(fingerprintHash);
        const now = Date.now();
        const windowMs = 60000;
        const maxRequestsPerMinute = 30;

        profile.requestTimestamps.push(now);
        profile.requestTimestamps = profile.requestTimestamps.filter(ts => now - ts < windowMs);
        profile.velocityScore = profile.requestTimestamps.length;
        profile.lastVelocityCheck = now;

        if (profile.velocityScore > maxRequestsPerMinute) {
            await this.recordSuspiciousActivity(fingerprintHash, {
                type: 'high_velocity',
                details: `${profile.velocityScore} requests in last minute (limit: ${maxRequestsPerMinute})`,
                severity: 'high',
            });
            await this.saveProfile(profile);
            return { allowed: false, velocityScore: profile.velocityScore };
        }

        await this.saveProfile(profile);
        return { allowed: true, velocityScore: profile.velocityScore };
    }

    /**
     * Check velocity limits
     */
    async checkVelocity(fingerprintHash: string): Promise<{ allowed: boolean; velocityScore: number; recommendedDelay?: number }> {
        const profile = await this.getProfile(fingerprintHash);
        const now = Date.now();

        profile.requestTimestamps = profile.requestTimestamps.filter(ts => now - ts < 60000);
        profile.velocityScore = profile.requestTimestamps.length;

        const maxRequests = 30;

        if (profile.velocityScore >= maxRequests) {
            const oldestTimestamp = profile.requestTimestamps[0];
            const recommendedDelay = oldestTimestamp ? (oldestTimestamp + 60000 - now) : 1000;
            return { allowed: false, velocityScore: profile.velocityScore, recommendedDelay };
        }

        return { allowed: true, velocityScore: profile.velocityScore };
    }

    /**
     * Record a challenge attempt
     */
    async recordChallengeAttempt(
        fingerprintHash: string,
        success: boolean,
        ip: string,
        suspicious?: { type: string; details: string; severity: 'low' | 'medium' | 'high' }
    ): Promise<void> {
        const profile = await this.getProfile(fingerprintHash);

        profile.lastSeen = Date.now();
        profile.totalRequests++;

        if (success) {
            profile.successfulChallenges++;
            profile.reputationScore = Math.min(100, profile.reputationScore + 2);
        } else {
            profile.failedChallenges++;
            profile.reputationScore = Math.max(0, profile.reputationScore - 5);
        }

        if (!profile.knownIPs.includes(ip)) {
            profile.knownIPs.push(ip);
            if (profile.knownIPs.length > 10) {
                await this.recordSuspiciousActivity(fingerprintHash, {
                    type: 'multiple_ips',
                    details: `Device seen from ${profile.knownIPs.length} different IPs`,
                    severity: 'medium',
                });
            }
        }

        if (suspicious) {
            await this.recordSuspiciousActivity(fingerprintHash, suspicious);
        }

        await this.checkBanConditions(profile);
        await this.saveProfile(profile);
    }

    /**
     * Record suspicious activity
     */
    async recordSuspiciousActivity(
        fingerprintHash: string,
        activity: { type: string; details: string; severity: 'low' | 'medium' | 'high' }
    ): Promise<void> {
        const profile = await this.getProfile(fingerprintHash);

        const suspiciousActivity: SuspiciousActivity = {
            timestamp: Date.now(),
            ...activity,
        };

        profile.suspiciousActivities.push(suspiciousActivity);

        if (profile.suspiciousActivities.length > this.maxSuspiciousActivities) {
            profile.suspiciousActivities = profile.suspiciousActivities.slice(-this.maxSuspiciousActivities);
        }

        const severityPenalty = { low: 3, medium: 10, high: 25 };
        profile.reputationScore = Math.max(0, profile.reputationScore - severityPenalty[activity.severity]);

        await this.saveProfile(profile);
    }

    /**
     * Evaluate device reputation
     */
    async evaluate(fingerprintHash: string): Promise<DeviceReputationResult> {
        const profile = await this.getProfile(fingerprintHash);

        if (profile.isBanned) {
            if (profile.banExpiry && Date.now() > profile.banExpiry) {
                profile.isBanned = false;
                profile.banReason = undefined;
                profile.banExpiry = undefined;
                profile.reputationScore = 20;
                await this.saveProfile(profile);
            } else {
                return {
                    fingerprintHash,
                    reputationScore: 0,
                    reputationLevel: 'malicious',
                    isBanned: true,
                    banReason: profile.banReason,
                    challengeMultiplier: 10,
                    recommendations: ['Block all requests'],
                };
            }
        }

        let reputationLevel: 'trusted' | 'neutral' | 'suspicious' | 'malicious';
        if (profile.reputationScore >= 80) reputationLevel = 'trusted';
        else if (profile.reputationScore >= 50) reputationLevel = 'neutral';
        else if (profile.reputationScore >= 20) reputationLevel = 'suspicious';
        else reputationLevel = 'malicious';

        let challengeMultiplier = 1;
        if (reputationLevel === 'suspicious') challengeMultiplier = 2;
        else if (reputationLevel === 'malicious') challengeMultiplier = 4;

        const recommendations: string[] = [];

        if (profile.failedChallenges > profile.successfulChallenges * 2) {
            recommendations.push('High failure rate - increase challenge difficulty');
        }

        if (profile.knownIPs.length > 5) {
            recommendations.push('Multiple IPs - verify IP consistency');
        }

        const recentSuspicious = profile.suspiciousActivities.filter(
            a => Date.now() - a.timestamp < 3600000
        );
        if (recentSuspicious.length > 3) {
            recommendations.push('Recent suspicious activity - require additional verification');
        }

        return {
            fingerprintHash,
            reputationScore: profile.reputationScore,
            reputationLevel,
            isBanned: false,
            challengeMultiplier,
            recommendations,
        };
    }

    /**
     * Ban a device
     */
    async banDevice(fingerprintHash: string, reason: string, durationMs?: number): Promise<void> {
        const profile = await this.getProfile(fingerprintHash);
        profile.isBanned = true;
        profile.banReason = reason;
        profile.reputationScore = 0;

        if (durationMs) {
            profile.banExpiry = Date.now() + durationMs;
        }

        await this.saveProfile(profile);
        await addToSet(BAN_SET_KEY, fingerprintHash);
    }

    /**
     * Unban a device
     */
    async unbanDevice(fingerprintHash: string): Promise<void> {
        const profile = await this.getProfile(fingerprintHash);
        profile.isBanned = false;
        profile.banReason = undefined;
        profile.banExpiry = undefined;
        profile.reputationScore = 20;
        await this.saveProfile(profile);
    }

    /**
     * Check ban conditions
     */
    private async checkBanConditions(profile: DeviceProfile): Promise<void> {
        const recentFailures = profile.suspiciousActivities.filter(
            a => a.type === 'challenge_failed' && Date.now() - a.timestamp < 3600000
        ).length;
        if (recentFailures > 20) {
            await this.banDevice(profile.fingerprintHash, 'Excessive failed challenges', 24 * 3600000);
            return;
        }

        const recentHighSeverity = profile.suspiciousActivities.filter(
            a => a.severity === 'high' && Date.now() - a.timestamp < 3600000
        ).length;
        if (recentHighSeverity >= 3) {
            await this.banDevice(profile.fingerprintHash, 'Multiple high-severity incidents', 12 * 3600000);
            return;
        }

        if (profile.reputationScore <= 5 && profile.totalRequests > 10) {
            await this.banDevice(profile.fingerprintHash, 'Reputation too low', 6 * 3600000);
            return;
        }
    }
}

// Singleton instance
export const deviceReputation = new DeviceReputationSystem();
