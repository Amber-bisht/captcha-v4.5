import crypto from 'crypto';

export interface PoWChallenge {
    nonce: string;
    difficulty: number; // Number of leading zeros required in hash
    timestamp: number;
}

export class PoWManager {
    /**
     * Generate a new PoW challenge based on risk
     * 
     * Difficulty Guide (SHA-256 with leading zeros):
     * - 3: ~8 iterations (~1ms) - TOO EASY
     * - 4: ~65K iterations (~130ms) - Minimum acceptable
     * - 5: ~1M iterations (~2s) - Good for suspicious users
     * - 6: ~16M iterations (~33s) - High risk / datacenters
     * - 7: ~268M iterations (~9min) - Critical / known attackers
     */
    static generateChallenge(riskScore: number): PoWChallenge {
        // BASE DIFFICULTY: 4 (economic cost for all users)
        // This provides ~130ms computational cost minimum
        let difficulty = 4;

        // Progressive scaling based on risk
        if (riskScore > 30) difficulty = 5;   // ~2s for mildly suspicious
        if (riskScore > 50) difficulty = 5;   // ~2s for medium risk
        if (riskScore > 70) difficulty = 6;   // ~33s for high risk
        if (riskScore > 90) difficulty = 7;   // ~9min for critical (effectively blocking)

        return {
            nonce: crypto.randomBytes(16).toString('hex'),
            difficulty,
            timestamp: Date.now()
        };
    }

    /**
     * Verify the PoW solution
     * Solution must be a string that, when hashed with nonce, produces 'difficulty' leading zeros
     */
    static verify(nonce: string, solution: string, difficulty: number): boolean {
        const hash = crypto.createHash('sha256')
            .update(nonce + solution)
            .digest('hex');

        const prefix = '0'.repeat(difficulty);
        return hash.startsWith(prefix);
    }
}
