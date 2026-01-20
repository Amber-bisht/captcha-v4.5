/**
 * Advanced Browser Fingerprinting System
 * 30+ signals for robust client identification
 */

import crypto from 'crypto';

export interface AdvancedFingerprint {
    // Basic signals
    userAgent: string;
    language: string;
    languages: string[];
    platform: string;
    hardwareConcurrency: number;
    deviceMemory: number;
    maxTouchPoints: number;

    // Screen signals
    screenWidth: number;
    screenHeight: number;
    screenColorDepth: number;
    screenPixelDepth: number;
    availWidth: number;
    availHeight: number;
    devicePixelRatio: number;

    // Timezone
    timezone: string;
    timezoneOffset: number;

    // Canvas fingerprint
    canvasHash: string;

    // WebGL signals
    webglVendor: string;
    webglRenderer: string;
    webglVersion: string;
    webglShadingVersion: string;
    webglExtensions: string[];
    webglHash: string;

    // Audio fingerprint
    audioHash: string;

    // Font detection
    fontsHash: string;
    fontsDetected: string[];

    // Plugin/MIME info
    pluginsHash: string;
    pluginCount: number;
    mimeTypesHash: string;
    mimeTypeCount: number;

    // Browser features
    cookiesEnabled: boolean;
    doNotTrack: string | null;
    localStorage: boolean;
    sessionStorage: boolean;
    indexedDB: boolean;

    // WebRTC (can reveal real IP behind VPN)
    webrtcLocalIPs: string[];
    webrtcPublicIP: string | null;

    // Battery API (if available)
    batteryCharging: boolean | null;
    batteryLevel: number | null;

    // Connection info
    connectionType: string | null;
    connectionDownlink: number | null;
    connectionRtt: number | null;

    // Additional browser quirks
    hasLiedLanguages: boolean;
    hasLiedResolution: boolean;
    hasLiedOs: boolean;
    hasLiedBrowser: boolean;

    // Speech synthesis voices
    speechVoicesHash: string;

    // Permissions
    permissionsHash: string;

    // CPU class (IE specific but useful)
    cpuClass: string | null;
}

export interface FingerprintAnalysis {
    hash: string;
    entropy: number;
    uniquenessScore: number;
    consistencyScore: number;
    suspiciousSignals: string[];
    riskLevel: 'low' | 'medium' | 'high';
}

export class AdvancedFingerprintAnalyzer {
    /**
     * Analyze an advanced fingerprint for consistency and suspiciousness
     */
    static analyze(fingerprint: Partial<AdvancedFingerprint>): FingerprintAnalysis {
        const suspiciousSignals: string[] = [];
        let consistencyScore = 100;

        // Check for inconsistencies

        // 1. Platform vs UserAgent mismatch
        if (fingerprint.userAgent && fingerprint.platform) {
            const ua = fingerprint.userAgent.toLowerCase();
            const platform = fingerprint.platform.toLowerCase();

            if (ua.includes('windows') && !platform.includes('win')) {
                suspiciousSignals.push('Platform mismatch: UA says Windows, platform disagrees');
                consistencyScore -= 20;
            }
            if (ua.includes('mac') && !platform.includes('mac')) {
                suspiciousSignals.push('Platform mismatch: UA says Mac, platform disagrees');
                consistencyScore -= 20;
            }
            if (ua.includes('linux') && !platform.includes('linux')) {
                suspiciousSignals.push('Platform mismatch: UA says Linux, platform disagrees');
                consistencyScore -= 15;
            }
        }

        // 2. Screen resolution anomalies
        if (fingerprint.screenWidth && fingerprint.screenHeight) {
            const ratio = fingerprint.screenWidth / fingerprint.screenHeight;
            // Unusual aspect ratios
            if (ratio < 0.5 || ratio > 3) {
                suspiciousSignals.push(`Unusual screen aspect ratio: ${ratio.toFixed(2)}`);
                consistencyScore -= 15;
            }
            // Exact common headless dimensions
            if (fingerprint.screenWidth === 800 && fingerprint.screenHeight === 600) {
                suspiciousSignals.push('Default headless browser resolution detected');
                consistencyScore -= 25;
            }
        }

        // 3. WebGL anomalies
        if (fingerprint.webglRenderer) {
            const renderer = fingerprint.webglRenderer.toLowerCase();
            const suspiciousRenderers = [
                'swiftshader',
                'llvmpipe',
                'mesa',
                'virtualbox',
                'vmware',
                'parallels',
            ];
            for (const suspicious of suspiciousRenderers) {
                if (renderer.includes(suspicious)) {
                    suspiciousSignals.push(`Suspicious WebGL renderer: ${suspicious}`);
                    consistencyScore -= 20;
                    break;
                }
            }
        }

        // 4. Plugin count anomalies
        if (fingerprint.pluginCount === 0 && fingerprint.userAgent) {
            const ua = fingerprint.userAgent.toLowerCase();
            if (!ua.includes('mobile') && !ua.includes('android') && !ua.includes('iphone')) {
                suspiciousSignals.push('Desktop browser with zero plugins');
                consistencyScore -= 15;
            }
        }

        // 5. Hardware concurrency anomalies
        if (fingerprint.hardwareConcurrency !== undefined) {
            if (fingerprint.hardwareConcurrency === 0) {
                suspiciousSignals.push('Hardware concurrency is 0');
                consistencyScore -= 20;
            }
            // Very high values might indicate spoofing
            if (fingerprint.hardwareConcurrency > 128) {
                suspiciousSignals.push('Unrealistic hardware concurrency value');
                consistencyScore -= 10;
            }
        }

        // 6. Language inconsistencies
        if (fingerprint.languages && fingerprint.language) {
            if (fingerprint.languages.length > 0 && !fingerprint.languages.includes(fingerprint.language)) {
                suspiciousSignals.push('Primary language not in languages array');
                consistencyScore -= 10;
            }
        }

        // 7. Lying indicators
        if (fingerprint.hasLiedBrowser) {
            suspiciousSignals.push('Browser fingerprint spoofing detected');
            consistencyScore -= 25;
        }
        if (fingerprint.hasLiedOs) {
            suspiciousSignals.push('OS fingerprint spoofing detected');
            consistencyScore -= 25;
        }
        if (fingerprint.hasLiedResolution) {
            suspiciousSignals.push('Screen resolution spoofing detected');
            consistencyScore -= 15;
        }
        if (fingerprint.hasLiedLanguages) {
            suspiciousSignals.push('Language spoofing detected');
            consistencyScore -= 10;
        }

        // 8. WebRTC leak check (if VPN but local IP visible)
        if (fingerprint.webrtcLocalIPs && fingerprint.webrtcLocalIPs.length > 0) {
            const hasPrivateIP = fingerprint.webrtcLocalIPs.some(ip =>
                ip.startsWith('192.168.') ||
                ip.startsWith('10.') ||
                ip.match(/^172\.(1[6-9]|2[0-9]|3[0-1])\./)
            );
            if (hasPrivateIP) {
                // Not necessarily suspicious, but useful info
                suspiciousSignals.push('WebRTC reveals local network IP');
            }
        }

        // Calculate hash
        const hash = this.generateHash(fingerprint);

        // Calculate entropy (how unique is this fingerprint)
        const entropy = this.calculateEntropy(fingerprint);

        // Uniqueness score based on entropy
        const uniquenessScore = Math.min(100, entropy * 5);

        // Determine risk level
        let riskLevel: 'low' | 'medium' | 'high';
        if (consistencyScore < 50 || suspiciousSignals.length >= 3) {
            riskLevel = 'high';
        } else if (consistencyScore < 75 || suspiciousSignals.length >= 1) {
            riskLevel = 'medium';
        } else {
            riskLevel = 'low';
        }

        return {
            hash,
            entropy,
            uniquenessScore,
            consistencyScore: Math.max(0, consistencyScore),
            suspiciousSignals,
            riskLevel,
        };
    }

    /**
     * Generate a stable hash from fingerprint components
     */
    static generateHash(fingerprint: Partial<AdvancedFingerprint>): string {
        const components = [
            fingerprint.userAgent || '',
            fingerprint.language || '',
            fingerprint.platform || '',
            fingerprint.hardwareConcurrency?.toString() || '',
            fingerprint.screenWidth?.toString() || '',
            fingerprint.screenHeight?.toString() || '',
            fingerprint.screenColorDepth?.toString() || '',
            fingerprint.timezone || '',
            fingerprint.canvasHash || '',
            fingerprint.webglRenderer || '',
            fingerprint.webglVendor || '',
            fingerprint.audioHash || '',
            fingerprint.fontsHash || '',
            fingerprint.pluginsHash || '',
        ].join('|||');

        return crypto.createHash('sha256').update(components).digest('hex');
    }

    /**
     * Calculate entropy of the fingerprint (uniqueness measure)
     */
    private static calculateEntropy(fingerprint: Partial<AdvancedFingerprint>): number {
        let entropy = 0;

        // Each signal contributes to entropy
        if (fingerprint.canvasHash) entropy += 4;
        if (fingerprint.webglHash) entropy += 3;
        if (fingerprint.audioHash) entropy += 3;
        if (fingerprint.fontsHash) entropy += 4;
        if (fingerprint.userAgent) entropy += 2;
        if (fingerprint.timezone) entropy += 1;
        if (fingerprint.screenWidth && fingerprint.screenHeight) entropy += 2;
        if (fingerprint.languages && fingerprint.languages.length > 0) entropy += 1;
        if (fingerprint.pluginsHash) entropy += 2;
        if (fingerprint.webrtcLocalIPs && fingerprint.webrtcLocalIPs.length > 0) entropy += 3;

        return entropy;
    }

    /**
     * Compare two fingerprints and return similarity score
     */
    static compareSimilarity(
        fp1: Partial<AdvancedFingerprint>,
        fp2: Partial<AdvancedFingerprint>
    ): number {
        let matches = 0;
        let total = 0;

        const compareField = (val1: any, val2: any, weight: number = 1) => {
            total += weight;
            if (val1 === val2 && val1 !== undefined) {
                matches += weight;
            }
        };

        compareField(fp1.canvasHash, fp2.canvasHash, 5);
        compareField(fp1.webglHash, fp2.webglHash, 4);
        compareField(fp1.audioHash, fp2.audioHash, 4);
        compareField(fp1.fontsHash, fp2.fontsHash, 4);
        compareField(fp1.userAgent, fp2.userAgent, 2);
        compareField(fp1.timezone, fp2.timezone, 2);
        compareField(fp1.screenWidth, fp2.screenWidth, 1);
        compareField(fp1.screenHeight, fp2.screenHeight, 1);
        compareField(fp1.language, fp2.language, 1);
        compareField(fp1.platform, fp2.platform, 1);
        compareField(fp1.hardwareConcurrency, fp2.hardwareConcurrency, 1);

        return total > 0 ? (matches / total) * 100 : 0;
    }
}
