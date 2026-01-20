"use strict";
/**
 * Client-Side Proof of Work Solver
 * Wrapped in IIFE to avoid global conflicts
 */
(function () {
    async function solveProofOfWork(challenge) {
        const startTime = performance.now();
        let nonce = 0;
        while (true) {
            const data = challenge.prefix + nonce.toString();
            const hashBuffer = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(data));
            const hashArray = Array.from(new Uint8Array(hashBuffer));
            const hash = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
            let zeros = 0;
            for (const char of hash) {
                if (char === '0')
                    zeros++;
                else
                    break;
            }
            if (zeros >= challenge.difficulty) {
                const computeTime = performance.now() - startTime;
                return { challengeId: challenge.id, nonce: nonce.toString(), hash, computeTime };
            }
            nonce++;
            if (nonce % 1000 === 0) {
                await new Promise(resolve => setTimeout(resolve, 0));
            }
            if (Date.now() > challenge.expiresAt) {
                throw new Error('Challenge expired while solving');
            }
        }
    }
    window.solveProofOfWork = solveProofOfWork;
})();
