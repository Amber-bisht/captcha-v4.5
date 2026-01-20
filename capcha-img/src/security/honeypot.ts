/**
 * Honeypot System - Invisible traps to catch automated bots
 */

import crypto from 'crypto';

export interface HoneypotField {
    name: string;
    type: 'text' | 'email' | 'hidden' | 'checkbox';
    expectedValue: string;
    isDecoy: boolean;
}

export interface HoneypotChallenge {
    id: string;
    fields: HoneypotField[];
    timestamp: number;
    expiresAt: number;
}

export interface HoneypotResult {
    passed: boolean;
    violations: string[];
    riskScore: number;
}

const DECOY_NAMES = [
    'email_confirm', 'website', 'url', 'phone2', 'company',
    'fax', 'address2', 'username2', 'confirm_email', 'your_name'
];

const honeypotStore = new Map<string, HoneypotChallenge>();

export class HoneypotSystem {
    private minSubmitTimeMs: number;
    private maxSubmitTimeMs: number;

    constructor(minSubmitTimeMs = 2000, maxSubmitTimeMs = 300000) {
        this.minSubmitTimeMs = minSubmitTimeMs;
        this.maxSubmitTimeMs = maxSubmitTimeMs;
    }

    generateChallenge(numFields = 3): HoneypotChallenge {
        const id = crypto.randomBytes(16).toString('hex');
        const timestamp = Date.now();

        const shuffled = [...DECOY_NAMES].sort(() => Math.random() - 0.5);
        const fields: HoneypotField[] = shuffled.slice(0, numFields).map(name => ({
            name: `hp_${crypto.randomBytes(4).toString('hex')}_${name}`,
            type: 'text' as const,
            expectedValue: '',
            isDecoy: true,
        }));

        // Add timing field
        fields.push({
            name: `_ts_${crypto.randomBytes(4).toString('hex')}`,
            type: 'hidden',
            expectedValue: timestamp.toString(),
            isDecoy: false,
        });

        const challenge: HoneypotChallenge = {
            id, fields, timestamp,
            expiresAt: timestamp + this.maxSubmitTimeMs,
        };

        honeypotStore.set(id, challenge);
        return challenge;
    }

    verify(challengeId: string, submittedFields: Record<string, string>): HoneypotResult {
        const violations: string[] = [];
        let riskScore = 0;
        const submitTime = Date.now();

        const challenge = honeypotStore.get(challengeId);
        if (!challenge) {
            return { passed: false, violations: ['Invalid challenge'], riskScore: 100 };
        }

        if (submitTime > challenge.expiresAt) {
            honeypotStore.delete(challengeId);
            return { passed: false, violations: ['Challenge expired'], riskScore: 50 };
        }

        const elapsed = submitTime - challenge.timestamp;
        if (elapsed < this.minSubmitTimeMs) {
            violations.push(`Submitted too fast: ${elapsed}ms`);
            riskScore += 40;
        }

        for (const field of challenge.fields) {
            if (field.isDecoy && submittedFields[field.name]?.trim()) {
                violations.push(`Honeypot field filled: ${field.name}`);
                riskScore += 30;
            }
        }

        honeypotStore.delete(challengeId);
        return { passed: violations.length === 0, violations, riskScore: Math.min(riskScore, 100) };
    }

    getClientConfig(challenge: HoneypotChallenge) {
        return {
            id: challenge.id,
            fields: challenge.fields.map(f => ({
                name: f.name, type: f.type,
                decoy: f.isDecoy, value: f.isDecoy ? '' : f.expectedValue,
            })),
        };
    }
}
