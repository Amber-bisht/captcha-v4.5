/**
 * Risk Scoring System
 * Calculates risk score BEFORE showing CAPTCHA
 * High-risk users get harder challenges or are blocked
 */

import { Request } from 'express';
import crypto from 'crypto';
import { deviceReputation } from './deviceReputation';
import { ipReputation } from './ipReputation';
import { PoWConfig } from './powManager';

// Known datacenter IP ranges (partial list - use ipinfo.io for full)
const DATACENTER_ASNS = new Set([
    'AWS', 'GOOGLE', 'MICROSOFT', 'DIGITALOCEAN', 'LINODE',
    'VULTR', 'OVH', 'HETZNER', 'CLOUDFLARE'
]);

// Suspicious User-Agent patterns
const SUSPICIOUS_UA_PATTERNS = [
    /headless/i, /phantom/i, /selenium/i, /webdriver/i,
    /puppeteer/i, /playwright/i, /python-requests/i,
    /curl/i, /wget/i, /http-client/i, /bot/i, /crawler/i,
    /spider/i, /scraper/i
];

// Known bot TLS fingerprints (JA3 hashes)
const BOT_TLS_FINGERPRINTS = new Set([
    '3e5b8b0d8e3c6f4a7b9c2d1e',  // Example Puppeteer
    '2a4c6e8f0b1d3a5c7e9d1b3f',  // Example Selenium
]);

export interface RiskScore {
    score: number;           // 0-100, higher = more suspicious
    level: 'low' | 'medium' | 'high' | 'critical';
    factors: RiskFactor[];
    challengeConfig: ChallengeConfig;
}

export interface RiskFactor {
    name: string;
    weight: number;
    details?: string;
}

export interface ChallengeConfig {
    skipCaptcha: boolean;
    difficulty: 'easy' | 'standard' | 'hard' | 'extreme';
    gridSize: 9 | 12 | 16;
    requireMultipleRounds: boolean;
    addImageDegradation: boolean;
    requireProofOfWork: boolean;
    powDifficulty: number;
    recommendedChallenge: 'text' | 'spatial';
    powAlgorithm: 'sha256' | 'scrypt'; // NEW: Algorithm selection
    scryptParams?: {
        N: number;
        r: number;
        p: number;
    };
}

export class RiskAnalyzer {
    /**
     * Calculate comprehensive risk score
     */
    static async calculateRiskScore(
        req: Request,
        behaviorData?: any
    ): Promise<RiskScore> {
        const factors: RiskFactor[] = [];
        let score = 0;

        // 1. IP-based checks (Enhanced with IP Reputation Service)
        const ipScore = await this.analyzeIP(req, factors);
        score += ipScore;

        // 2. User-Agent analysis
        const uaScore = this.analyzeUserAgent(req, factors);
        score += uaScore;

        // 3. Header analysis
        const headerScore = this.analyzeHeaders(req, factors);
        score += headerScore;

        // 4. TLS fingerprint (if available)
        const tlsScore = this.analyzeTLSFingerprint(req, factors);
        score += tlsScore;

        // 5. Device Reputation Check (NEW)
        if ((req as any).fingerprint?.hash) {
            const deviceStatus = deviceReputation.evaluate((req as any).fingerprint.hash);
            if (deviceStatus.reputationLevel === 'malicious') {
                score += 50;
                factors.push({ name: 'malicious_device', weight: 50, details: 'Device flagged as malicious' });
            } else if (deviceStatus.reputationLevel === 'suspicious') {
                score += 25;
                factors.push({ name: 'suspicious_device', weight: 25, details: 'Device flagged as suspicious' });
            }
        }

        // 6. Behavioral analysis
        if (behaviorData) {
            const behaviorScore = this.analyzeBehavior(behaviorData, factors);
            score += behaviorScore;
        }

        // 7. Request timing patterns
        const timingScore = this.analyzeRequestTiming(req, factors);
        score += timingScore;

        // Cap at 100
        score = Math.min(score, 100);

        // Determine level and config
        const level = this.getLevel(score);
        const challengeConfig = this.getChallengeConfig(level);

        return { score, level, factors, challengeConfig };
    }

    /**
     * Analyze IP address for risk indicators
     */
    private static async analyzeIP(req: Request, factors: RiskFactor[]): Promise<number> {
        let score = 0;
        const ip = this.getClientIP(req);
        const ua = req.headers['user-agent'];

        // Use IP Reputation Service
        const ipResult = await ipReputation.getReputation(ip, ua);

        if (ipResult.riskScore > 0) {
            // Apply IPQS/Local score (capped contribution)
            const contribution = Math.min(ipResult.riskScore, 60);
            score += contribution;
            factors.push({ name: 'ip_reputation', weight: contribution, details: `Risk Score: ${ipResult.riskScore}` });

            if (ipResult.isDatacenter) {
                factors.push({ name: 'datacenter_ip', weight: 0, details: 'Datacenter/Hosting IP' });
            }
            if (ipResult.isTor) {
                factors.push({ name: 'tor_exit', weight: 0, details: 'Tor Exit Node' });
            }
            if (ipResult.isProxy) {
                factors.push({ name: 'proxy_detected', weight: 0, details: 'Proxy/VPN Detected' });
            }
            if (ipResult.isBot) {
                factors.push({ name: 'bot_ip', weight: 0, details: 'Known Bot IP' });
            }
        }

        // Check header consistency
        const forwardedFor = req.headers['x-forwarded-for'];
        const realIp = req.headers['x-real-ip'];
        if (forwardedFor && realIp && !String(forwardedFor).includes(String(realIp))) {
            score += 15;
            factors.push({ name: 'ip_mismatch', weight: 15, details: 'IP header inconsistency' });
        }

        return score;
    }

    /**
     * Analyze User-Agent for automation indicators
     */
    private static analyzeUserAgent(req: Request, factors: RiskFactor[]): number {
        let score = 0;
        const ua = req.headers['user-agent'] || '';

        // Empty User-Agent
        if (!ua) {
            score += 40;
            factors.push({ name: 'missing_ua', weight: 40, details: 'No User-Agent header' });
            return score;
        }

        // Check suspicious patterns
        for (const pattern of SUSPICIOUS_UA_PATTERNS) {
            if (pattern.test(ua)) {
                score += 45;
                factors.push({ name: 'suspicious_ua', weight: 45, details: `UA matches: ${pattern}` });
                break;
            }
        }

        // Check for outdated browser
        const chromeMatch = ua.match(/Chrome\/(\d+)/);
        if (chromeMatch && parseInt(chromeMatch[1]) < 90) {
            score += 10;
            factors.push({ name: 'outdated_browser', weight: 10, details: 'Very old Chrome version' });
        }

        // Check for known headless indicators in UA
        if (ua.includes('HeadlessChrome')) {
            score += 50;
            factors.push({ name: 'headless_chrome', weight: 50, details: 'HeadlessChrome detected' });
        }

        return score;
    }

    /**
     * Analyze HTTP headers for automation indicators
     */
    private static analyzeHeaders(req: Request, factors: RiskFactor[]): number {
        let score = 0;

        // Missing Accept-Language (most bots forget this)
        if (!req.headers['accept-language']) {
            score += 20;
            factors.push({ name: 'missing_accept_lang', weight: 20, details: 'No Accept-Language header' });
        }

        // Missing Accept-Encoding
        if (!req.headers['accept-encoding']) {
            score += 15;
            factors.push({ name: 'missing_accept_enc', weight: 15, details: 'No Accept-Encoding header' });
        }

        // Check Sec-Fetch-* headers (modern browsers only)
        const secFetchSite = req.headers['sec-fetch-site'];
        const secFetchMode = req.headers['sec-fetch-mode'];
        const secFetchDest = req.headers['sec-fetch-dest'];

        // Bots often have inconsistent Sec-Fetch-* headers
        if (secFetchSite === 'cross-site' && secFetchMode === 'navigate') {
            score += 10;
            factors.push({ name: 'suspicious_sec_fetch', weight: 10, details: 'Unusual Sec-Fetch combination' });
        }

        // Check for missing modern headers that real browsers send
        if (!req.headers['sec-ch-ua'] && req.headers['user-agent']?.includes('Chrome')) {
            score += 15;
            factors.push({ name: 'missing_client_hints', weight: 15, details: 'Chrome without Client Hints' });
        }

        return score;
    }

    /**
     * Analyze TLS fingerprint (JA3/JA4)
     */
    private static analyzeTLSFingerprint(req: Request, factors: RiskFactor[]): number {
        let score = 0;

        // TLS fingerprint should be set by nginx/reverse proxy
        const tlsFingerprint = req.headers['x-tls-fingerprint'] as string;

        if (tlsFingerprint && BOT_TLS_FINGERPRINTS.has(tlsFingerprint)) {
            score += 60;
            factors.push({ name: 'bot_tls_fingerprint', weight: 60, details: 'Known bot TLS signature' });
        }

        return score;
    }

    /**
     * Analyze behavioral data
     */
    private static analyzeBehavior(behaviorData: any, factors: RiskFactor[]): number {
        let score = 0;

        // Too fast submission
        if (behaviorData.totalTime && behaviorData.totalTime < 1000) {
            score += 30;
            factors.push({ name: 'too_fast', weight: 30, details: 'Submission under 1 second' });
        }

        // No mouse movements
        if (behaviorData.mouseMovements !== undefined && behaviorData.mouseMovements < 5) {
            score += 20;
            factors.push({ name: 'no_mouse', weight: 20, details: 'Minimal mouse movement' });
        }

        // Perfect timing (low variance = bot)
        if (behaviorData.timingVariance !== undefined && behaviorData.timingVariance < 30) {
            score += 25;
            factors.push({ name: 'robotic_timing', weight: 25, details: 'Timing too consistent' });
        }

        // Straight line movements
        if (behaviorData.straightLineRatio !== undefined && behaviorData.straightLineRatio > 0.8) {
            score += 20;
            factors.push({ name: 'straight_lines', weight: 20, details: 'Mouse moves in straight lines' });
        }

        return score;
    }

    /**
     * Analyze request timing patterns
     */
    private static analyzeRequestTiming(req: Request, factors: RiskFactor[]): number {
        // This would check Redis for recent requests from this IP/fingerprint
        // Implement pattern detection for scripted delays
        return 0;
    }

    /**
     * Get risk level from score
     */
    private static getLevel(score: number): 'low' | 'medium' | 'high' | 'critical' {
        if (score < 25) return 'low';
        if (score < 50) return 'medium';
        if (score < 75) return 'high';
        return 'critical';
    }

    /**
     * Get challenge configuration based on risk level
     */
    /**
     * Get challenge configuration based on risk level
     * SECURITY: Always use spatial CAPTCHA - text CAPTCHA is ML-solvable
     */
    /**
     * Get challenge configuration based on risk level
     * SECURITY: Always use spatial CAPTCHA - text CAPTCHA is ML-solvable
     */
    private static getChallengeConfig(level: 'low' | 'medium' | 'high' | 'critical'): ChallengeConfig {
        switch (level) {
            case 'low':
                return {
                    skipCaptcha: false,
                    difficulty: 'standard',
                    gridSize: 9,
                    requireMultipleRounds: false,
                    addImageDegradation: false,
                    requireProofOfWork: true,
                    powDifficulty: 4,
                    powAlgorithm: 'sha256',
                    recommendedChallenge: 'spatial'
                };

            case 'medium':
                return {
                    skipCaptcha: false,
                    difficulty: 'standard',
                    gridSize: 9,
                    requireMultipleRounds: false,
                    addImageDegradation: true,
                    requireProofOfWork: true,
                    powDifficulty: 5,
                    powAlgorithm: 'sha256',
                    recommendedChallenge: 'spatial'
                };

            case 'high':
                return {
                    skipCaptcha: false,
                    difficulty: 'hard',
                    gridSize: 12,
                    requireMultipleRounds: true,
                    addImageDegradation: true,
                    requireProofOfWork: true,
                    powDifficulty: 6,
                    powAlgorithm: 'scrypt', // GPU-Resistant
                    scryptParams: { N: 16384, r: 8, p: 1 },
                    recommendedChallenge: 'spatial'
                };

            case 'critical':
                return {
                    skipCaptcha: false,
                    difficulty: 'extreme',
                    gridSize: 16,
                    requireMultipleRounds: true,
                    addImageDegradation: true,
                    requireProofOfWork: true,
                    powDifficulty: 7,
                    powAlgorithm: 'scrypt', // GPU-Resistant
                    scryptParams: { N: 32768, r: 8, p: 2 }, // Harder Scrypt
                    recommendedChallenge: 'spatial'
                };
        }
    }

    // Helper methods

    private static getClientIP(req: Request): string {
        return (
            (req.headers['x-forwarded-for'] as string)?.split(',')[0] ||
            (req.headers['x-real-ip'] as string) ||
            req.socket.remoteAddress ||
            'unknown'
        );
    }

    private static isDatacenterIP(ip: string): boolean {
        // In production, use a service like ipinfo.io or ipqualityscore
        // This is a simplified check
        const datacenterRanges = [
            /^35\./, /^34\./, /^104\./, /^23\./, // Google/AWS partial
            /^52\./, /^54\./, /^18\./, /^13\./   // AWS partial
        ];
        return datacenterRanges.some(pattern => pattern.test(ip));
    }

    private static async isTorExitNode(ip: string): Promise<boolean> {
        // In production, check against TOR exit node list
        // https://check.torproject.org/torbulkexitlist
        return false;
    }
}

export default RiskAnalyzer;
