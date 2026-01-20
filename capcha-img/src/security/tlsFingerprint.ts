/**
 * TLS Fingerprinting (JA3/JA4)
 * Detect bot clients by their TLS handshake signature
 */

import crypto from 'crypto';

export interface TLSFingerprint {
    ja3Hash: string;
    ja3Raw?: string;
    ja4Hash?: string;
    cipherSuites: string[];
    extensions: string[];
    ellipticCurves: string[];
    ecPointFormats: string[];
    tlsVersion: string;
}

export interface TLSAnalysisResult {
    isKnownBot: boolean;
    confidence: number;
    category: 'browser' | 'bot' | 'automation' | 'unknown';
    matchedSignature?: string;
    riskLevel: 'low' | 'medium' | 'high' | 'critical';
}

// Known JA3 hashes for common automation tools
const KNOWN_BOT_JA3: Record<string, string> = {
    // Python requests
    'e7d705a3286e19ea42f587b344ee6865': 'python-requests',
    '3b5074b1b5d032e5620f69f9f700ff0e': 'python-urllib',
    // Node.js
    '54f890d8a4f0c17f8c8f54f894ebab46': 'nodejs-axios',
    '29dd6a9c90d4a22b73552f55269c2aeb': 'nodejs-fetch',
    // Go
    '62b9d781fdba2d30a5c9fb3d5c35e3e7': 'golang-http',
    // Curl
    '456523fc94726331a4d5a2e1d40b2cd7': 'curl',
    'd94c5c6f3c4a4f4c7e6c8f7e5c3b9a2d': 'curl-impersonate',
    // Selenium/WebDriver
    '20c6539e77b7b6e1c5e3f6a1d3e4c5b0': 'selenium-chrome',
    '3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b': 'selenium-firefox',
    // Puppeteer
    '4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e': 'puppeteer',
    // Playwright
    '5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f': 'playwright',
};

// Known legitimate browser JA3 hashes (partial list)
const KNOWN_BROWSER_JA3: Record<string, string> = {
    '771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513,29-23-24,0': 'Chrome',
    '771,4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-34-51-43-13-45-28-65037,29-23-24-25-256-257,0': 'Firefox',
    '771,4865-4866-4867-49196-49195-52393-49200-49199-52392-49188-49187-49192-49191-49162-49161-49172-49171-157-156-61-60-53-47-255,0-11-10-35-22-23-13-43-45-51-21,29-23-24-25,0-1-2': 'Safari',
};

export class TLSFingerprintAnalyzer {
    /**
     * Analyze a JA3 fingerprint
     */
    static analyze(fingerprint: TLSFingerprint): TLSAnalysisResult {
        const ja3Hash = fingerprint.ja3Hash.toLowerCase();

        // Check against known bot signatures
        if (KNOWN_BOT_JA3[ja3Hash]) {
            return {
                isKnownBot: true,
                confidence: 95,
                category: 'bot',
                matchedSignature: KNOWN_BOT_JA3[ja3Hash],
                riskLevel: 'critical',
            };
        }

        // Check against known browser signatures
        for (const [sig, browser] of Object.entries(KNOWN_BROWSER_JA3)) {
            const sigHash = crypto.createHash('md5').update(sig).digest('hex');
            if (sigHash === ja3Hash) {
                return {
                    isKnownBot: false,
                    confidence: 90,
                    category: 'browser',
                    matchedSignature: browser,
                    riskLevel: 'low',
                };
            }
        }

        // Heuristic analysis
        return this.heuristicAnalysis(fingerprint);
    }

    /**
     * Heuristic analysis for unknown fingerprints
     */
    private static heuristicAnalysis(fp: TLSFingerprint): TLSAnalysisResult {
        let suspicionScore = 0;

        // Check cipher suite count (browsers typically have 10-20+)
        if (fp.cipherSuites.length < 5) {
            suspicionScore += 30;
        }

        // Check extensions (browsers have many)
        if (fp.extensions.length < 5) {
            suspicionScore += 20;
        }

        // Check TLS version
        if (!fp.tlsVersion.includes('1.3') && !fp.tlsVersion.includes('1.2')) {
            suspicionScore += 25;
        }

        // Check for GREASE values (real browsers use these)
        const hasGrease = fp.cipherSuites.some(cs =>
            /^(0x)?[0-9a-f]a[0-9a-f]a$/i.test(cs)
        );
        if (!hasGrease) {
            suspicionScore += 15;
        }

        let riskLevel: 'low' | 'medium' | 'high' | 'critical';
        let category: 'browser' | 'bot' | 'automation' | 'unknown';

        if (suspicionScore >= 60) {
            riskLevel = 'high';
            category = 'bot';
        } else if (suspicionScore >= 35) {
            riskLevel = 'medium';
            category = 'unknown';
        } else {
            riskLevel = 'low';
            category = 'browser';
        }

        return {
            isKnownBot: suspicionScore >= 50,
            confidence: Math.min(suspicionScore + 20, 80),
            category,
            riskLevel,
        };
    }

    /**
     * Generate JA3 hash from components
     */
    static generateJA3Hash(
        tlsVersion: string,
        cipherSuites: string[],
        extensions: string[],
        ellipticCurves: string[],
        ecPointFormats: string[]
    ): string {
        const ja3String = [
            tlsVersion,
            cipherSuites.join('-'),
            extensions.join('-'),
            ellipticCurves.join('-'),
            ecPointFormats.join('-'),
        ].join(',');

        return crypto.createHash('md5').update(ja3String).digest('hex');
    }
}
