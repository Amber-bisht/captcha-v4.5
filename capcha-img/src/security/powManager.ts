import crypto from 'crypto';
import { scryptSync } from 'crypto';

export interface PoWChallenge {
    nonce: string;
    difficulty: number; // Number of leading zeros required in hash
    timestamp: number;
    algorithm: 'sha256' | 'scrypt'; // Algorithm to use
    scryptParams?: {
        N: number;  // CPU/memory cost parameter (power of 2)
        r: number;  // Block size
        p: number;  // Parallelization parameter
    };
}

export interface PoWConfig {
    useScrypt: boolean;
    scryptN: number;
    scryptR: number;
    scryptP: number;
}

// Default scrypt parameters (memory-hard, GPU-resistant)
// N=16384 uses ~16MB RAM, ~100ms on modern CPU
// N=32768 uses ~32MB RAM, ~200ms on modern CPU
const DEFAULT_SCRYPT_PARAMS = {
    N: 16384,  // 2^14 - moderate memory requirement
    r: 8,      // Block size
    p: 1       // Parallelization
};

// High security scrypt params for suspicious users
const HIGH_SECURITY_SCRYPT_PARAMS = {
    N: 32768,  // 2^15 - ~32MB RAM, ~200ms
    r: 8,
    p: 2       // More iterations
};

export class PoWManager {
    /**
     * Generate a new PoW challenge based on risk
     * 
     * SHA-256 Difficulty Guide (leading zeros):
     * - 3: ~8 iterations (~1ms) - TOO EASY
     * - 4: ~65K iterations (~130ms) - Minimum acceptable
     * - 5: ~1M iterations (~2s) - Good for suspicious users
     * - 6: ~16M iterations (~33s) - High risk / datacenters
     * - 7: ~268M iterations (~9min) - Critical / known attackers
     * 
     * Scrypt (GPU-resistant, memory-hard):
     * - Uses memory and sequential operations
     * - Cannot be parallelized efficiently on GPUs
     * - Each solve requires dedicated RAM allocation
     */
    static generateChallenge(riskScore: number, useScrypt: boolean = false): PoWChallenge {
        // BASE DIFFICULTY: 4 (economic cost for all users)
        let difficulty = 4;
        let algorithm: 'sha256' | 'scrypt' = useScrypt ? 'scrypt' : 'sha256';
        let scryptParams = DEFAULT_SCRYPT_PARAMS;

        // Progressive scaling based on risk
        if (riskScore > 30) difficulty = 5;
        if (riskScore > 50) difficulty = 5;
        if (riskScore > 70) {
            difficulty = 6;
            // Use higher scrypt params for high risk
            if (useScrypt) {
                scryptParams = HIGH_SECURITY_SCRYPT_PARAMS;
            }
        }
        if (riskScore > 90) {
            difficulty = 7;
            if (useScrypt) {
                scryptParams = {
                    N: 65536, // 2^16 - ~64MB RAM
                    r: 8,
                    p: 4
                };
            }
        }

        const challenge: PoWChallenge = {
            nonce: crypto.randomBytes(16).toString('hex'),
            difficulty,
            timestamp: Date.now(),
            algorithm
        };

        if (useScrypt) {
            challenge.scryptParams = scryptParams;
        }

        return challenge;
    }

    /**
     * Verify the PoW solution using SHA-256 (original, fast)
     */
    static verifySHA256(nonce: string, solution: string, difficulty: number): boolean {
        const hash = crypto.createHash('sha256')
            .update(nonce + solution)
            .digest('hex');

        const prefix = '0'.repeat(difficulty);
        return hash.startsWith(prefix);
    }

    /**
     * Verify the PoW solution using scrypt (GPU-resistant)
     * Scrypt is memory-hard, meaning GPUs cannot efficiently parallelize it
     */
    static verifyScrypt(
        nonce: string,
        solution: string,
        difficulty: number,
        params: { N: number; r: number; p: number }
    ): boolean {
        try {
            // Create scrypt hash
            const salt = Buffer.from(nonce, 'hex');
            const key = scryptSync(
                solution,
                salt,
                32, // Output length
                {
                    N: params.N,
                    r: params.r,
                    p: params.p,
                    maxmem: params.N * params.r * 128 * 2 // Memory limit
                }
            );

            // Convert to hex and check leading zeros
            const hash = key.toString('hex');
            const prefix = '0'.repeat(difficulty);
            return hash.startsWith(prefix);
        } catch (error) {
            console.error('[PoW] Scrypt verification error:', error);
            return false;
        }
    }

    /**
     * Verify the PoW solution (auto-detects algorithm)
     */
    static verify(
        nonce: string,
        solution: string,
        difficulty: number,
        algorithm?: 'sha256' | 'scrypt',
        scryptParams?: { N: number; r: number; p: number }
    ): boolean {
        // Default to SHA-256 for backward compatibility
        if (!algorithm || algorithm === 'sha256') {
            return this.verifySHA256(nonce, solution, difficulty);
        }

        if (algorithm === 'scrypt') {
            return this.verifyScrypt(
                nonce,
                solution,
                difficulty,
                scryptParams || DEFAULT_SCRYPT_PARAMS
            );
        }

        return false;
    }

    /**
     * Estimate solve time for a given configuration
     */
    static estimateSolveTime(difficulty: number, algorithm: 'sha256' | 'scrypt'): string {
        if (algorithm === 'sha256') {
            const iterations = Math.pow(16, difficulty);
            const hashesPerSecond = 500000; // Conservative estimate for browser
            const seconds = iterations / hashesPerSecond;

            if (seconds < 1) return `~${Math.round(seconds * 1000)}ms`;
            if (seconds < 60) return `~${Math.round(seconds)}s`;
            return `~${Math.round(seconds / 60)}min`;
        } else {
            // Scrypt is much slower due to memory requirements
            const baseTimeMs = 100; // Base time for one scrypt operation
            const iterations = Math.pow(16, difficulty - 2); // Fewer iterations needed
            const totalMs = baseTimeMs * iterations;

            if (totalMs < 1000) return `~${Math.round(totalMs)}ms`;
            if (totalMs < 60000) return `~${Math.round(totalMs / 1000)}s`;
            return `~${Math.round(totalMs / 60000)}min`;
        }
    }
}

