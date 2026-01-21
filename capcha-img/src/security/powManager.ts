import crypto from 'crypto';

export interface PoWChallenge {
    nonce: string;
    difficulty: number; // Number of leading zeros required in hash
    timestamp: number;
}

export class PoWManager {
    /**
     * Generate a new PoW challenge based on risk
     */
    static generateChallenge(riskScore: number): PoWChallenge {
        // Difficulty scales: 1 (easy) to 6 (very hard)
        // 3 is usually ~500ms on a modern laptop
        let difficulty = 3;
        if (riskScore > 50) difficulty = 4;
        if (riskScore > 80) difficulty = 5;

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
