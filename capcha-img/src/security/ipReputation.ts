/**
 * IP Reputation Service
 * 
 * Provides IP risk assessment using:
 * 1. Local heuristics (datacenter ranges, known bad IPs)
 * 2. Optional IPQualityScore API integration
 * 3. Local caching to reduce API calls
 */

import crypto from 'crypto';

// Cache for IP reputation results
const ipCache = new Map<string, { result: IPReputationResult; expires: number }>();
const CACHE_TTL_MS = 5 * 60 * 1000; // 5 minutes

// Known datacenter/cloud provider IP ranges (partial list for common providers)
const DATACENTER_PATTERNS = [
    // AWS
    /^52\.(0|1[0-9]|2[0-9]|3[0-9]|[4-9][0-9]|[1-2][0-9]{2})\./,
    /^54\./,
    /^3\.([0-9]{1,3})\./,
    /^18\./,
    // Google Cloud
    /^35\.(186|187|188|189|190|191|192|193|194|195|196|197|198|199|20[0-9]|21[0-9]|22[0-9]|23[0-5])\./,
    /^34\./,
    // Azure
    /^13\.([0-9]{1,3})\./,
    /^20\.(0|1[0-9]|[2-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\./,
    /^40\./,
    /^52\.1[0-9]{2}\./,
    // DigitalOcean
    /^104\.131\./,
    /^104\.236\./,
    /^138\.68\./,
    /^139\.59\./,
    /^159\.65\./,
    /^167\.99\./,
    /^174\.138\./,
    /^178\.62\./,
    // Linode
    /^45\.79\./,
    /^66\.228\./,
    /^96\.126\./,
    /^139\.162\./,
    // Vultr
    /^45\.32\./,
    /^45\.63\./,
    /^45\.76\./,
    /^104\.156\./,
    /^104\.207\./,
    /^108\.61\./,
    /^66\.55\./,
    // OVH
    /^51\.68\./,
    /^51\.75\./,
    /^51\.77\./,
    /^51\.78\./,
    /^51\.79\./,
    /^51\.81\./,
    /^51\.83\./,
    /^51\.89\./,
    /^51\.91\./,
    /^51\.195\./,
    // Hetzner
    /^116\.202\./,
    /^116\.203\./,
    /^138\.201\./,
    /^144\.76\./,
    /^148\.251\./,
    /^178\.63\./,
    /^195\.201\./,
    /^49\.12\./,
    /^49\.13\./,
];

// Known Tor exit node user agents (partial)
const TOR_BROWSER_SIGNATURES = [
    /Mozilla\/5\.0 \(Windows NT 10\.0; rv:.*\) Gecko\/20100101 Firefox\/.*$/,
    /Mozilla\/5\.0 \(Windows NT 6\.1; rv:.*\) Gecko\/20100101 Firefox\/.*$/,
];

export interface IPReputationResult {
    ip: string;
    riskScore: number; // 0-100, higher = more risky
    isVPN: boolean;
    isProxy: boolean;
    isDatacenter: boolean;
    isTor: boolean;
    isBot: boolean;
    country?: string;
    isp?: string;
    recommendations: string[];
    source: 'local' | 'api' | 'cache';
}

export interface IPQualityScoreConfig {
    apiKey: string;
    strictness?: 0 | 1 | 2 | 3; // 0 = lenient, 3 = strict
    timeout?: number;
}

/**
 * IP Reputation Service
 */
export class IPReputationService {
    private apiKey?: string;
    private strictness: number;
    private timeout: number;
    private enabled: boolean;

    constructor(config?: IPQualityScoreConfig) {
        this.apiKey = config?.apiKey || process.env.IPQS_API_KEY;
        this.strictness = config?.strictness ?? 1;
        // Reduced timeout to prevent slow init - fallback to local heuristics if API is slow
        this.timeout = config?.timeout ?? 1500;
        this.enabled = !!this.apiKey;
    }

    /**
     * Check IP reputation using local heuristics
     */
    private checkLocalHeuristics(ip: string, userAgent?: string): IPReputationResult {
        const result: IPReputationResult = {
            ip,
            riskScore: 0,
            isVPN: false,
            isProxy: false,
            isDatacenter: false,
            isTor: false,
            isBot: false,
            recommendations: [],
            source: 'local'
        };

        // Check against datacenter IP patterns
        for (const pattern of DATACENTER_PATTERNS) {
            if (pattern.test(ip)) {
                result.isDatacenter = true;
                result.riskScore += 40;
                result.recommendations.push('Datacenter IP detected - increase PoW difficulty');
                break;
            }
        }

        // Check for Tor browser signature
        if (userAgent) {
            for (const pattern of TOR_BROWSER_SIGNATURES) {
                if (pattern.test(userAgent)) {
                    result.isTor = true;
                    result.riskScore += 50;
                    result.recommendations.push('Tor browser signature detected');
                    break;
                }
            }
        }

        // Check for IPv6 (often residential, but can be datacenter)
        if (ip.includes(':')) {
            // IPv6 addresses are harder to analyze locally
            result.riskScore += 5;
        }

        // Check for localhost/private IPs (shouldn't reach production)
        if (ip.startsWith('127.') || ip.startsWith('192.168.') || ip.startsWith('10.') ||
            ip === 'localhost' || ip === '::1') {
            result.riskScore = 0;
            result.recommendations.push('Private/local IP - development environment');
        }

        return result;
    }

    /**
     * Check IP reputation using IPQualityScore API
     */
    private async checkIPQualityScore(ip: string): Promise<IPReputationResult | null> {
        if (!this.apiKey) {
            return null;
        }

        try {
            const controller = new AbortController();
            const timeoutId = setTimeout(() => controller.abort(), this.timeout);

            const response = await fetch(
                `https://ipqualityscore.com/api/json/ip/${this.apiKey}/${ip}?strictness=${this.strictness}&allow_public_access_points=true&fast=true&lighter_penalties=false`,
                { signal: controller.signal }
            );

            clearTimeout(timeoutId);

            if (!response.ok) {
                console.error(`[IPQS] API error: ${response.status}`);
                return null;
            }

            // Type the API response
            interface IPQSResponse {
                success: boolean;
                message?: string;
                fraud_score?: number;
                vpn?: boolean;
                proxy?: boolean;
                host?: boolean;
                tor?: boolean;
                bot_status?: boolean;
                country_code?: string;
                ISP?: string;
            }

            const data = await response.json() as IPQSResponse;

            if (!data.success) {
                console.error(`[IPQS] Request failed: ${data.message}`);
                return null;
            }

            const result: IPReputationResult = {
                ip,
                riskScore: data.fraud_score || 0,
                isVPN: data.vpn || false,
                isProxy: data.proxy || false,
                isDatacenter: data.host || false,
                isTor: data.tor || false,
                isBot: data.bot_status || false,
                country: data.country_code,
                isp: data.ISP,
                recommendations: [],
                source: 'api'
            };

            // Generate recommendations based on findings
            if (result.isVPN) {
                result.recommendations.push('VPN detected - consider additional verification');
            }
            if (result.isProxy) {
                result.recommendations.push('Proxy detected - increase challenge difficulty');
            }
            if (result.isTor) {
                result.recommendations.push('Tor exit node - require strong verification');
            }
            if (result.isDatacenter) {
                result.recommendations.push('Hosting provider IP - likely automated');
            }
            if (result.isBot) {
                result.recommendations.push('Known bot IP - consider blocking');
            }
            if (result.riskScore > 75) {
                result.recommendations.push('High fraud score - block or require maximum PoW');
            }

            return result;
        } catch (error: unknown) {
            const err = error as Error;
            if (err.name === 'AbortError') {
                console.error('[IPQS] Request timed out');
            } else {
                console.error('[IPQS] Error:', err.message);
            }
            return null;
        }
    }

    /**
     * Get IP reputation (uses cache, local heuristics, and optionally API)
     */
    async getReputation(ip: string, userAgent?: string): Promise<IPReputationResult> {
        // Check cache first
        const cacheKey = crypto.createHash('md5').update(ip).digest('hex');
        const cached = ipCache.get(cacheKey);

        if (cached && cached.expires > Date.now()) {
            return { ...cached.result, source: 'cache' };
        }

        // Try API first if enabled
        if (this.enabled) {
            const apiResult = await this.checkIPQualityScore(ip);
            if (apiResult) {
                // Cache the result
                ipCache.set(cacheKey, {
                    result: apiResult,
                    expires: Date.now() + CACHE_TTL_MS
                });
                return apiResult;
            }
        }

        // Fall back to local heuristics
        const localResult = this.checkLocalHeuristics(ip, userAgent);

        // Cache local results too (shorter TTL)
        ipCache.set(cacheKey, {
            result: localResult,
            expires: Date.now() + (CACHE_TTL_MS / 2)
        });

        return localResult;
    }

    /**
     * Quick check if IP should be challenged more aggressively
     * Returns risk multiplier (1 = normal, 2+ = increased difficulty)
     */
    async getRiskMultiplier(ip: string, userAgent?: string): Promise<number> {
        const reputation = await this.getReputation(ip, userAgent);

        if (reputation.isBot) return 10; // Extreme difficulty
        if (reputation.isTor) return 4;
        if (reputation.isProxy || reputation.isVPN) return 3;
        if (reputation.isDatacenter) return 2;
        if (reputation.riskScore > 85) return 4;
        if (reputation.riskScore > 70) return 3;
        if (reputation.riskScore > 50) return 2;
        if (reputation.riskScore > 30) return 1.5;

        return 1;
    }

    /**
     * Clear IP from cache (e.g., after successful verification)
     */
    clearCache(ip: string): void {
        const cacheKey = crypto.createHash('md5').update(ip).digest('hex');
        ipCache.delete(cacheKey);
    }

    /**
     * Get cache statistics
     */
    getStats(): { size: number; enabled: boolean } {
        return {
            size: ipCache.size,
            enabled: this.enabled
        };
    }
}

// Singleton instance
export const ipReputation = new IPReputationService();
