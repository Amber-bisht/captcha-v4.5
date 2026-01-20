/**
 * Request Anomaly Detection System
 * Detects coordinated attacks, credential stuffing, and suspicious patterns
 */

import crypto from 'crypto';

export interface RequestSignature {
    ip: string;
    fingerprint: string;
    userAgent: string;
    timestamp: number;
    endpoint: string;
    success: boolean;
}

export interface AnomalyResult {
    isAnomaly: boolean;
    anomalyScore: number; // 0-100
    anomalyType: string[];
    riskLevel: 'low' | 'medium' | 'high' | 'critical';
    recommendation: 'allow' | 'challenge' | 'block' | 'shadowban';
}

export interface AttackPattern {
    type: string;
    confidence: number;
    details: string;
    affectedIPs: string[];
    startTime: number;
    endTime: number;
}

// Sliding window for request tracking
interface RequestWindow {
    requests: RequestSignature[];
    failureCount: number;
    successCount: number;
    uniqueFingerprints: Set<string>;
    uniqueIPs: Set<string>;
}

export class RequestAnomalyDetector {
    private ipWindows: Map<string, RequestWindow> = new Map();
    private fingerprintWindows: Map<string, RequestWindow> = new Map();
    private globalWindow: RequestWindow;
    private windowDurationMs: number = 300000; // 5 minutes
    private attackPatterns: AttackPattern[] = [];

    constructor() {
        this.globalWindow = this.createEmptyWindow();

        // Cleanup old data periodically
        setInterval(() => this.cleanup(), 60000);
    }

    private createEmptyWindow(): RequestWindow {
        return {
            requests: [],
            failureCount: 0,
            successCount: 0,
            uniqueFingerprints: new Set(),
            uniqueIPs: new Set(),
        };
    }

    /**
     * Record a request and analyze for anomalies
     */
    recordAndAnalyze(request: RequestSignature): AnomalyResult {
        // Update windows
        this.updateWindow(this.ipWindows, request.ip, request);
        this.updateWindow(this.fingerprintWindows, request.fingerprint, request);
        this.updateGlobalWindow(request);

        // Analyze for anomalies
        return this.detectAnomalies(request);
    }

    private updateWindow(map: Map<string, RequestWindow>, key: string, request: RequestSignature): void {
        let window = map.get(key);
        if (!window) {
            window = this.createEmptyWindow();
            map.set(key, window);
        }

        // Remove old requests
        const cutoff = Date.now() - this.windowDurationMs;
        window.requests = window.requests.filter(r => r.timestamp > cutoff);

        // Add new request
        window.requests.push(request);

        // Update counters
        if (request.success) {
            window.successCount++;
        } else {
            window.failureCount++;
        }

        window.uniqueFingerprints.add(request.fingerprint);
        window.uniqueIPs.add(request.ip);
    }

    private updateGlobalWindow(request: RequestSignature): void {
        const cutoff = Date.now() - this.windowDurationMs;
        this.globalWindow.requests = this.globalWindow.requests.filter(r => r.timestamp > cutoff);
        this.globalWindow.requests.push(request);
        this.globalWindow.uniqueFingerprints.add(request.fingerprint);
        this.globalWindow.uniqueIPs.add(request.ip);
    }

    private detectAnomalies(request: RequestSignature): AnomalyResult {
        const anomalyTypes: string[] = [];
        let anomalyScore = 0;

        const ipWindow = this.ipWindows.get(request.ip);
        const fpWindow = this.fingerprintWindows.get(request.fingerprint);

        // 1. Velocity anomaly - too many requests from same IP
        if (ipWindow && ipWindow.requests.length > 10) {
            const requestsPerMinute = (ipWindow.requests.length / this.windowDurationMs) * 60000;
            if (requestsPerMinute > 5) {
                anomalyTypes.push('high_velocity_ip');
                anomalyScore += 25;
            }
            if (requestsPerMinute > 15) {
                anomalyScore += 25;
            }
        }

        // 2. Fingerprint anomaly - same fingerprint from multiple IPs
        if (fpWindow && fpWindow.uniqueIPs.size > 3) {
            anomalyTypes.push('fingerprint_ip_mismatch');
            anomalyScore += 20 + (fpWindow.uniqueIPs.size * 5);
        }

        // 3. IP anomaly - same IP with multiple fingerprints (fingerprint rotation)
        if (ipWindow && ipWindow.uniqueFingerprints.size > 5) {
            anomalyTypes.push('fingerprint_rotation');
            anomalyScore += 30;
        }

        // 4. Failure ratio anomaly - high failure rate indicates brute force
        if (ipWindow && ipWindow.failureCount > 3) {
            const failureRatio = ipWindow.failureCount / (ipWindow.failureCount + ipWindow.successCount);
            if (failureRatio > 0.8) {
                anomalyTypes.push('high_failure_rate');
                anomalyScore += 35;
            } else if (failureRatio > 0.5) {
                anomalyScore += 15;
            }
        }

        // 5. Timing anomaly - requests at exact intervals (bot pattern)
        if (ipWindow && ipWindow.requests.length >= 5) {
            const intervals = this.calculateIntervals(ipWindow.requests);
            const variance = this.calculateVariance(intervals);
            if (variance < 100 && intervals.length > 3) { // Very uniform timing
                anomalyTypes.push('uniform_request_timing');
                anomalyScore += 30;
            }
        }

        // 6. Credential stuffing pattern - many unique fingerprints, mostly failures
        if (this.globalWindow.requests.length > 50) {
            const recentFailures = this.globalWindow.requests.filter(r => !r.success).length;
            const failureRatio = recentFailures / this.globalWindow.requests.length;
            const uniqueFpRatio = this.globalWindow.uniqueFingerprints.size / this.globalWindow.requests.length;

            if (failureRatio > 0.7 && uniqueFpRatio > 0.5) {
                anomalyTypes.push('credential_stuffing_pattern');
                anomalyScore += 40;

                // Record attack pattern
                this.recordAttackPattern({
                    type: 'credential_stuffing',
                    confidence: Math.min(failureRatio * 100, 95),
                    details: `High failure rate (${(failureRatio * 100).toFixed(1)}%) with diverse fingerprints`,
                    affectedIPs: Array.from(this.globalWindow.uniqueIPs),
                    startTime: Math.min(...this.globalWindow.requests.map(r => r.timestamp)),
                    endTime: Date.now(),
                });
            }
        }

        // 7. Distributed attack detection - many IPs, similar patterns
        if (this.globalWindow.uniqueIPs.size > 20) {
            const requestsPerIP = this.globalWindow.requests.length / this.globalWindow.uniqueIPs.size;
            if (requestsPerIP < 3 && this.globalWindow.requests.length > 50) {
                anomalyTypes.push('distributed_attack');
                anomalyScore += 35;

                this.recordAttackPattern({
                    type: 'distributed_attack',
                    confidence: 80,
                    details: `${this.globalWindow.uniqueIPs.size} IPs with similar request patterns`,
                    affectedIPs: Array.from(this.globalWindow.uniqueIPs),
                    startTime: Math.min(...this.globalWindow.requests.map(r => r.timestamp)),
                    endTime: Date.now(),
                });
            }
        }

        // Calculate risk level and recommendation
        const riskLevel = this.calculateRiskLevel(anomalyScore);
        const recommendation = this.getRecommendation(anomalyScore, anomalyTypes);

        return {
            isAnomaly: anomalyScore >= 30,
            anomalyScore: Math.min(anomalyScore, 100),
            anomalyType: anomalyTypes,
            riskLevel,
            recommendation,
        };
    }

    private calculateIntervals(requests: RequestSignature[]): number[] {
        const sorted = requests.slice().sort((a, b) => a.timestamp - b.timestamp);
        const intervals: number[] = [];
        for (let i = 1; i < sorted.length; i++) {
            intervals.push(sorted[i].timestamp - sorted[i - 1].timestamp);
        }
        return intervals;
    }

    private calculateVariance(values: number[]): number {
        if (values.length === 0) return Infinity;
        const mean = values.reduce((a, b) => a + b, 0) / values.length;
        const squaredDiffs = values.map(v => Math.pow(v - mean, 2));
        return squaredDiffs.reduce((a, b) => a + b, 0) / values.length;
    }

    private calculateRiskLevel(score: number): 'low' | 'medium' | 'high' | 'critical' {
        if (score >= 70) return 'critical';
        if (score >= 50) return 'high';
        if (score >= 30) return 'medium';
        return 'low';
    }

    private getRecommendation(score: number, types: string[]): 'allow' | 'challenge' | 'block' | 'shadowban' {
        if (score >= 80 || types.includes('credential_stuffing_pattern')) {
            return 'block';
        }
        if (score >= 60 || types.includes('distributed_attack')) {
            return 'shadowban'; // Let them think they succeeded but don't process
        }
        if (score >= 30) {
            return 'challenge';
        }
        return 'allow';
    }

    private recordAttackPattern(pattern: AttackPattern): void {
        // Only keep patterns from last hour
        const hourAgo = Date.now() - 3600000;
        this.attackPatterns = this.attackPatterns.filter(p => p.endTime > hourAgo);
        this.attackPatterns.push(pattern);
    }

    /**
     * Get current attack patterns
     */
    getAttackPatterns(): AttackPattern[] {
        return this.attackPatterns;
    }

    /**
     * Check if an IP is part of an ongoing attack
     */
    isPartOfAttack(ip: string): boolean {
        return this.attackPatterns.some(p => p.affectedIPs.includes(ip));
    }

    private cleanup(): void {
        const cutoff = Date.now() - this.windowDurationMs;

        for (const [key, window] of this.ipWindows.entries()) {
            window.requests = window.requests.filter(r => r.timestamp > cutoff);
            if (window.requests.length === 0) {
                this.ipWindows.delete(key);
            }
        }

        for (const [key, window] of this.fingerprintWindows.entries()) {
            window.requests = window.requests.filter(r => r.timestamp > cutoff);
            if (window.requests.length === 0) {
                this.fingerprintWindows.delete(key);
            }
        }
    }
}
