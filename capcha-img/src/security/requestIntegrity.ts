/**
 * Request Signing & Integrity System
 * Ensures requests haven't been tampered with
 */

import crypto from 'crypto';

export interface SignedRequest {
    payload: any;
    signature: string;
    timestamp: number;
    nonce: string;
    clientId: string;
}

export interface VerificationResult {
    valid: boolean;
    error?: string;
    tamperedFields?: string[];
}

export interface IntegrityChallenge {
    id: string;
    challenge: string;
    expectedResponse: string;
    algorithm: string;
    createdAt: number;
    expiresAt: number;
}

const usedNonces = new Map<string, number>();
const integrityChallenges = new Map<string, IntegrityChallenge>();

export class RequestIntegritySystem {
    private secretKey: string;
    private nonceValidityMs: number = 300000; // 5 minutes
    private maxTimeDrift: number = 30000; // 30 seconds

    constructor(secretKey?: string) {
        this.secretKey = secretKey || crypto.randomBytes(32).toString('hex');
    }

    /**
     * Generate a client-side signing key (derived from server secret + client ID)
     */
    generateClientKey(clientId: string): string {
        return crypto
            .createHmac('sha256', this.secretKey)
            .update(clientId)
            .digest('hex');
    }

    /**
     * Sign a payload for a client
     */
    signPayload(payload: any, clientId: string): SignedRequest {
        const nonce = crypto.randomBytes(16).toString('hex');
        const timestamp = Date.now();

        const clientKey = this.generateClientKey(clientId);
        const dataToSign = JSON.stringify({ payload, timestamp, nonce, clientId });

        const signature = crypto
            .createHmac('sha256', clientKey)
            .update(dataToSign)
            .digest('hex');

        return {
            payload,
            signature,
            timestamp,
            nonce,
            clientId,
        };
    }

    /**
     * Verify a signed request
     */
    verifySignature(signedRequest: SignedRequest): VerificationResult {
        const { payload, signature, timestamp, nonce, clientId } = signedRequest;

        // Check timestamp (prevent replay with old requests)
        const now = Date.now();
        if (Math.abs(now - timestamp) > this.maxTimeDrift) {
            return { valid: false, error: 'Request timestamp too old or in future' };
        }

        // Check nonce (prevent replay)
        const nonceKey = `${clientId}:${nonce}`;
        if (usedNonces.has(nonceKey)) {
            return { valid: false, error: 'Nonce already used (replay attack)' };
        }

        // Verify signature
        const clientKey = this.generateClientKey(clientId);
        const dataToSign = JSON.stringify({ payload, timestamp, nonce, clientId });
        const expectedSignature = crypto
            .createHmac('sha256', clientKey)
            .update(dataToSign)
            .digest('hex');

        if (!crypto.timingSafeEqual(
            Buffer.from(signature, 'hex'),
            Buffer.from(expectedSignature, 'hex')
        )) {
            return { valid: false, error: 'Invalid signature' };
        }

        // Mark nonce as used
        usedNonces.set(nonceKey, now);

        // Cleanup old nonces
        this.cleanupNonces();

        return { valid: true };
    }

    /**
     * Create integrity challenge (to verify JS execution)
     */
    createIntegrityChallenge(): IntegrityChallenge {
        const id = crypto.randomBytes(16).toString('hex');
        const challenge = crypto.randomBytes(32).toString('hex');

        // Create a challenge that requires JS to solve
        const operations = [
            { op: 'reverse', fn: (s: string) => s.split('').reverse().join('') },
            { op: 'hash', fn: (s: string) => crypto.createHash('sha256').update(s).digest('hex').slice(0, 16) },
            {
                op: 'xor', fn: (s: string) => {
                    const key = 0x42;
                    return s.split('').map(c => String.fromCharCode(c.charCodeAt(0) ^ key)).join('');
                }
            },
        ];

        const selectedOp = operations[Math.floor(Math.random() * operations.length)];
        const expectedResponse = selectedOp.fn(challenge);

        const integrityChallenge: IntegrityChallenge = {
            id,
            challenge,
            expectedResponse,
            algorithm: selectedOp.op,
            createdAt: Date.now(),
            expiresAt: Date.now() + 60000, // 1 minute
        };

        integrityChallenges.set(id, integrityChallenge);

        // Return challenge without expected response
        return {
            ...integrityChallenge,
            expectedResponse: '', // Don't send to client
        };
    }

    /**
     * Verify integrity challenge response
     */
    verifyIntegrityChallenge(challengeId: string, response: string): boolean {
        const challenge = integrityChallenges.get(challengeId);

        if (!challenge) {
            return false;
        }

        if (Date.now() > challenge.expiresAt) {
            integrityChallenges.delete(challengeId);
            return false;
        }

        const valid = challenge.expectedResponse === response;

        // Delete challenge after use
        integrityChallenges.delete(challengeId);

        return valid;
    }

    /**
     * Generate integrity check script for client
     */
    generateClientIntegrityScript(challengeId: string, challenge: string, algorithm: string): string {
        const scripts: Record<string, string> = {
            reverse: `
        function solve(c) { return c.split('').reverse().join(''); }
        document.getElementById('_ic_${challengeId}').value = solve('${challenge}');
      `,
            hash: `
        async function solve(c) {
          const encoder = new TextEncoder();
          const data = encoder.encode(c);
          const hash = await crypto.subtle.digest('SHA-256', data);
          const arr = Array.from(new Uint8Array(hash));
          return arr.map(b => b.toString(16).padStart(2, '0')).join('').slice(0, 16);
        }
        solve('${challenge}').then(r => document.getElementById('_ic_${challengeId}').value = r);
      `,
            xor: `
        function solve(c) {
          const key = 0x42;
          return c.split('').map(char => String.fromCharCode(char.charCodeAt(0) ^ key)).join('');
        }
        document.getElementById('_ic_${challengeId}').value = solve('${challenge}');
      `,
        };

        return scripts[algorithm] || '';
    }

    private cleanupNonces(): void {
        const cutoff = Date.now() - this.nonceValidityMs;
        for (const [key, timestamp] of usedNonces.entries()) {
            if (timestamp < cutoff) {
                usedNonces.delete(key);
            }
        }
    }
}

/**
 * Request tampering detection
 */
export class TamperDetector {
    /**
     * Check for common tampering indicators
     */
    static analyze(request: {
        headers: Record<string, string | string[] | undefined>;
        body: any;
        query: any;
    }): { tampered: boolean; indicators: string[] } {
        const indicators: string[] = [];

        // 1. Check for proxy headers that shouldn't be there
        const suspiciousHeaders = [
            'x-forwarded-host',
            'x-original-url',
            'x-rewrite-url',
            'x-override-url',
        ];
        for (const header of suspiciousHeaders) {
            if (request.headers[header]) {
                indicators.push(`Suspicious header: ${header}`);
            }
        }

        // 2. Check for SQL injection patterns
        const sqlPatterns = [/('|"|;|--|\|\||&&)/i, /(union|select|insert|delete|drop|update|exec)/i];
        const checkValue = (val: any, path: string) => {
            if (typeof val === 'string') {
                for (const pattern of sqlPatterns) {
                    if (pattern.test(val)) {
                        indicators.push(`SQL injection pattern in ${path}`);
                        break;
                    }
                }
            }
        };

        // Check body
        if (request.body && typeof request.body === 'object') {
            for (const [key, val] of Object.entries(request.body)) {
                checkValue(val, `body.${key}`);
            }
        }

        // Check query
        if (request.query && typeof request.query === 'object') {
            for (const [key, val] of Object.entries(request.query)) {
                checkValue(val, `query.${key}`);
            }
        }

        // 3. Check for XSS patterns
        const xssPatterns = [/<script/i, /javascript:/i, /on\w+\s*=/i, /<iframe/i];
        const checkXSS = (val: any, path: string) => {
            if (typeof val === 'string') {
                for (const pattern of xssPatterns) {
                    if (pattern.test(val)) {
                        indicators.push(`XSS pattern in ${path}`);
                        break;
                    }
                }
            }
        };

        if (request.body && typeof request.body === 'object') {
            for (const [key, val] of Object.entries(request.body)) {
                checkXSS(val, `body.${key}`);
            }
        }

        // 4. Check for path traversal
        const traversalPatterns = [/\.\./g, /%2e%2e/gi, /\.%2e/gi, /%2e\./gi];
        const checkTraversal = (val: any, path: string) => {
            if (typeof val === 'string') {
                for (const pattern of traversalPatterns) {
                    if (pattern.test(val)) {
                        indicators.push(`Path traversal pattern in ${path}`);
                        break;
                    }
                }
            }
        };

        if (request.query && typeof request.query === 'object') {
            for (const [key, val] of Object.entries(request.query)) {
                checkTraversal(val, `query.${key}`);
            }
        }

        return {
            tampered: indicators.length > 0,
            indicators,
        };
    }
}
