/**
 * Device Reputation System
 * Tracks device behavior over time and assigns reputation scores
 */

import crypto from 'crypto';

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
    challengeMultiplier: number; // 1 = normal, 2 = harder, etc.
    recommendations: string[];
}

// In-memory store (use Redis in production)
const deviceProfiles = new Map<string, DeviceProfile>();
const bannedDevices = new Set<string>();

export class DeviceReputationSystem {
    private decayRate: number = 0.99; // Daily decay for reputation
    private maxSuspiciousActivities: number = 100;

    /**
     * Get or create a device profile
     */
    getProfile(fingerprintHash: string): DeviceProfile {
        let profile = deviceProfiles.get(fingerprintHash);

        if (!profile) {
            profile = {
                fingerprintHash,
                firstSeen: Date.now(),
                lastSeen: Date.now(),
                totalRequests: 0,
                successfulChallenges: 0,
                failedChallenges: 0,
                suspiciousActivities: [],
                knownIPs: [],
                reputationScore: 50, // Start neutral
                isBanned: false,
            };
            deviceProfiles.set(fingerprintHash, profile);
        }

        return profile;
    }

    /**
     * Record a challenge attempt
     */
    recordChallengeAttempt(
        fingerprintHash: string,
        success: boolean,
        ip: string,
        suspicious?: { type: string; details: string; severity: 'low' | 'medium' | 'high' }
    ): void {
        const profile = this.getProfile(fingerprintHash);

        profile.lastSeen = Date.now();
        profile.totalRequests++;

        if (success) {
            profile.successfulChallenges++;
            // Increase reputation for successful challenges
            profile.reputationScore = Math.min(100, profile.reputationScore + 2);
        } else {
            profile.failedChallenges++;
            // Decrease reputation for failed challenges
            profile.reputationScore = Math.max(0, profile.reputationScore - 5);
        }

        // Track IP
        if (!profile.knownIPs.includes(ip)) {
            profile.knownIPs.push(ip);
            // Suspicious if too many IPs
            if (profile.knownIPs.length > 10) {
                this.recordSuspiciousActivity(fingerprintHash, {
                    type: 'multiple_ips',
                    details: `Device seen from ${profile.knownIPs.length} different IPs`,
                    severity: 'medium',
                });
            }
        }

        // Record suspicious activity if provided
        if (suspicious) {
            this.recordSuspiciousActivity(fingerprintHash, suspicious);
        }

        // Check for ban conditions
        this.checkBanConditions(profile);
    }

    /**
     * Record suspicious activity
     */
    recordSuspiciousActivity(
        fingerprintHash: string,
        activity: { type: string; details: string; severity: 'low' | 'medium' | 'high' }
    ): void {
        const profile = this.getProfile(fingerprintHash);

        const suspiciousActivity: SuspiciousActivity = {
            timestamp: Date.now(),
            ...activity,
        };

        profile.suspiciousActivities.push(suspiciousActivity);

        // Limit stored activities
        if (profile.suspiciousActivities.length > this.maxSuspiciousActivities) {
            profile.suspiciousActivities = profile.suspiciousActivities.slice(-this.maxSuspiciousActivities);
        }

        // Decrease reputation based on severity
        const severityPenalty = { low: 3, medium: 10, high: 25 };
        profile.reputationScore = Math.max(0, profile.reputationScore - severityPenalty[activity.severity]);
    }

    /**
     * Evaluate device reputation
     */
    evaluate(fingerprintHash: string): DeviceReputationResult {
        const profile = this.getProfile(fingerprintHash);

        // Check if banned
        if (profile.isBanned) {
            if (profile.banExpiry && Date.now() > profile.banExpiry) {
                // Ban expired
                profile.isBanned = false;
                profile.banReason = undefined;
                profile.banExpiry = undefined;
                profile.reputationScore = 20; // Start with low reputation after ban
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

        // Calculate reputation level
        let reputationLevel: 'trusted' | 'neutral' | 'suspicious' | 'malicious';
        if (profile.reputationScore >= 80) {
            reputationLevel = 'trusted';
        } else if (profile.reputationScore >= 50) {
            reputationLevel = 'neutral';
        } else if (profile.reputationScore >= 20) {
            reputationLevel = 'suspicious';
        } else {
            reputationLevel = 'malicious';
        }

        // Calculate challenge multiplier
        let challengeMultiplier = 1;
        if (reputationLevel === 'suspicious') {
            challengeMultiplier = 2;
        } else if (reputationLevel === 'malicious') {
            challengeMultiplier = 4;
        }

        // Generate recommendations
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

        // Account age bonus
        const ageInDays = (Date.now() - profile.firstSeen) / 86400000;
        if (ageInDays > 30 && profile.reputationScore >= 60) {
            recommendations.push('Established device - consider reducing friction');
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
    banDevice(fingerprintHash: string, reason: string, durationMs?: number): void {
        const profile = this.getProfile(fingerprintHash);
        profile.isBanned = true;
        profile.banReason = reason;
        profile.reputationScore = 0;

        if (durationMs) {
            profile.banExpiry = Date.now() + durationMs;
        }

        bannedDevices.add(fingerprintHash);
    }

    /**
     * Unban a device
     */
    unbanDevice(fingerprintHash: string): void {
        const profile = deviceProfiles.get(fingerprintHash);
        if (profile) {
            profile.isBanned = false;
            profile.banReason = undefined;
            profile.banExpiry = undefined;
            profile.reputationScore = 20;
        }
        bannedDevices.delete(fingerprintHash);
    }

    /**
     * Check if a device should be banned
     */
    private checkBanConditions(profile: DeviceProfile): void {
        // Auto-ban conditions

        // 1. Too many failures in short time
        const recentFailures = profile.suspiciousActivities.filter(
            a => a.type === 'challenge_failed' && Date.now() - a.timestamp < 3600000
        ).length;
        if (recentFailures > 20) {
            this.banDevice(profile.fingerprintHash, 'Excessive failed challenges', 24 * 3600000);
            return;
        }

        // 2. Multiple high-severity suspicious activities
        const recentHighSeverity = profile.suspiciousActivities.filter(
            a => a.severity === 'high' && Date.now() - a.timestamp < 3600000
        ).length;
        if (recentHighSeverity >= 3) {
            this.banDevice(profile.fingerprintHash, 'Multiple high-severity incidents', 12 * 3600000);
            return;
        }

        // 3. Reputation too low
        if (profile.reputationScore <= 5 && profile.totalRequests > 10) {
            this.banDevice(profile.fingerprintHash, 'Reputation too low', 6 * 3600000);
            return;
        }
    }

    /**
     * Apply daily decay to all reputations
     */
    applyDecay(): void {
        for (const profile of deviceProfiles.values()) {
            if (profile.reputationScore > 50) {
                // Decay good reputation slowly
                profile.reputationScore = 50 + (profile.reputationScore - 50) * this.decayRate;
            } else if (profile.reputationScore < 50) {
                // Recover bad reputation slowly
                profile.reputationScore = 50 - (50 - profile.reputationScore) * this.decayRate;
            }
        }
    }

    /**
     * Get statistics
     */
    getStats(): {
        totalDevices: number;
        bannedDevices: number;
        averageReputation: number;
        reputationDistribution: Record<string, number>;
    } {
        let totalReputation = 0;
        const distribution = { trusted: 0, neutral: 0, suspicious: 0, malicious: 0 };

        for (const profile of deviceProfiles.values()) {
            totalReputation += profile.reputationScore;

            if (profile.reputationScore >= 80) distribution.trusted++;
            else if (profile.reputationScore >= 50) distribution.neutral++;
            else if (profile.reputationScore >= 20) distribution.suspicious++;
            else distribution.malicious++;
        }

        return {
            totalDevices: deviceProfiles.size,
            bannedDevices: bannedDevices.size,
            averageReputation: deviceProfiles.size > 0 ? totalReputation / deviceProfiles.size : 50,
            reputationDistribution: distribution,
        };
    }
}

// Singleton instance
export const deviceReputation = new DeviceReputationSystem();
