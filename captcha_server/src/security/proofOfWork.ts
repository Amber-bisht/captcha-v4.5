/**
 * Proof-of-Work Challenge System
 * Requires clients to solve computational puzzles before accessing CAPTCHA
 * This adds significant cost to automated attacks
 * 
 * NOW USES REDIS for challenge storage
 */

import crypto from 'crypto';
import { powChallengeStore, StoredPoWChallenge } from './powChallengeStore';

export interface PoWChallenge {
    id: string;
    prefix: string;
    difficulty: number; // Number of leading zeros required
    timestamp: number;
    expiresAt: number;
    algorithm: 'sha256' | 'sha384' | 'sha512';
}

export interface PoWSolution {
    challengeId: string;
    nonce: string;
    hash: string;
}

export interface PoWVerificationResult {
    valid: boolean;
    error?: string;
    computeTime?: number;
    hashRate?: number;
}

export interface PoWConfig {
    baseDifficulty: number;
    suspiciousDifficultyMultiplier: number;
    expirationMs: number;
    minComputeTimeMs: number;
    maxComputeTimeMs: number;
}

const DEFAULT_CONFIG: PoWConfig = {
    baseDifficulty: 5,
    suspiciousDifficultyMultiplier: 2,
    expirationMs: 45000,
    minComputeTimeMs: 200,
    maxComputeTimeMs: 30000,
};

// challengeStore is now Redis-backed via powChallengeStore

export class ProofOfWorkSystem {
    private config: PoWConfig;

    constructor(config: Partial<PoWConfig> = {}) {
        this.config = { ...DEFAULT_CONFIG, ...config };
    }

    /**
     * Generate a new PoW challenge
     * @param riskLevel - Higher risk = higher difficulty
     */
    async generateChallenge(riskLevel: 'low' | 'medium' | 'high' | 'critical' = 'low'): Promise<PoWChallenge> {
        const id = crypto.randomBytes(16).toString('hex');
        const prefix = crypto.randomBytes(32).toString('hex');
        const timestamp = Date.now();

        // Adjust difficulty based on risk level
        let difficulty = this.config.baseDifficulty;
        switch (riskLevel) {
            case 'medium':
                difficulty += 1;
                break;
            case 'high':
                difficulty += 2;
                break;
            case 'critical':
                difficulty += 3;
                break;
        }

        const challenge: PoWChallenge = {
            id,
            prefix,
            difficulty,
            timestamp,
            expiresAt: timestamp + this.config.expirationMs,
            algorithm: 'sha256',
        };

        // Store challenge in Redis
        await powChallengeStore.set(id, { ...challenge, createdAt: Date.now() });

        return challenge;
    }

    /**
     * Verify a PoW solution
     */
    async verifySolution(solution: PoWSolution, clientComputeTime?: number): Promise<PoWVerificationResult> {
        // Get the challenge
        const stored = await powChallengeStore.get(solution.challengeId);
        if (!stored) {
            return { valid: false, error: 'Challenge not found or expired' };
        }

        // Check expiration
        if (Date.now() > stored.expiresAt) {
            await powChallengeStore.delete(solution.challengeId);
            return { valid: false, error: 'Challenge expired' };
        }

        // Calculate the expected hash
        const data = stored.prefix + solution.nonce;
        const hash = crypto.createHash(stored.algorithm).update(data).digest('hex');

        // Verify the hash matches what the client sent
        if (hash !== solution.hash) {
            return { valid: false, error: 'Hash mismatch' };
        }

        // Verify the hash meets the difficulty requirement
        const leadingZeros = this.countLeadingZeros(hash);
        if (leadingZeros < stored.difficulty) {
            return { valid: false, error: 'Insufficient proof of work' };
        }

        // Check compute time if provided
        if (clientComputeTime !== undefined) {
            if (clientComputeTime < this.config.minComputeTimeMs) {
                return {
                    valid: false,
                    error: 'Suspiciously fast computation (pre-computed solution?)'
                };
            }
            if (clientComputeTime > this.config.maxComputeTimeMs) {
                return {
                    valid: false,
                    error: 'Computation took too long'
                };
            }
        }

        // Delete the challenge to prevent reuse
        await powChallengeStore.delete(solution.challengeId);

        // Calculate hash rate if compute time is provided
        let hashRate: number | undefined;
        if (clientComputeTime) {
            // Estimate iterations based on nonce value
            const nonceNum = parseInt(solution.nonce, 10);
            if (!isNaN(nonceNum)) {
                hashRate = (nonceNum / (clientComputeTime / 1000)); // hashes per second
            }
        }

        return {
            valid: true,
            computeTime: clientComputeTime,
            hashRate
        };
    }

    /**
     * Count leading zeros in a hex string
     */
    private countLeadingZeros(hash: string): number {
        let count = 0;
        for (const char of hash) {
            if (char === '0') {
                count++;
            } else {
                break;
            }
        }
        return count;
    }

    /**
     * Get estimated iterations for a difficulty level
     */
    static getEstimatedIterations(difficulty: number): number {
        // Each hex character represents 4 bits
        // Probability of random hex being '0' is 1/16
        // For n leading zeros, probability is (1/16)^n
        // Expected iterations = 16^n
        return Math.pow(16, difficulty);
    }

    /**
     * Get estimated time in milliseconds for a difficulty level
     * Based on ~500k SHA256 operations per second on modern browser
     */
    static getEstimatedTimeMs(difficulty: number): number {
        const iterations = this.getEstimatedIterations(difficulty);
        const hashesPerSecond = 500000;
        return (iterations / hashesPerSecond) * 1000;
    }
}

/**
 * Client-side PoW solver (to be transpiled to JS)
 * This is a reference implementation - actual client code is in public/
 */
export const CLIENT_POW_SOLVER = `
async function solveProofOfWork(challenge) {
  const startTime = performance.now();
  let nonce = 0;
  
  while (true) {
    const data = challenge.prefix + nonce.toString();
    const hashBuffer = await crypto.subtle.digest('SHA-256', 
      new TextEncoder().encode(data)
    );
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    const hash = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
    
    // Check leading zeros
    let zeros = 0;
    for (const char of hash) {
      if (char === '0') zeros++;
      else break;
    }
    
    if (zeros >= challenge.difficulty) {
      const computeTime = performance.now() - startTime;
      return {
        challengeId: challenge.id,
        nonce: nonce.toString(),
        hash: hash,
        computeTime: computeTime
      };
    }
    
    nonce++;
    
    // Yield to prevent blocking
    if (nonce % 1000 === 0) {
      await new Promise(resolve => setTimeout(resolve, 0));
    }
  }
}
`;
