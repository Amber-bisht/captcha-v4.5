/**
 * Multi-Stage Challenge System
 * Risk-based challenge escalation
 */

import crypto from 'crypto';

export type ChallengeType =
    | 'pow'           // Proof of Work
    | 'honeypot'      // Honeypot fields
    | 'text_captcha'  // Text CAPTCHA
    | 'image_captcha' // Image selection
    | 'audio_captcha' // Audio challenge
    | 'puzzle'        // Visual puzzle
    | 'behavioral';   // Behavioral verification only

export interface ChallengeStage {
    type: ChallengeType;
    difficulty: number; // 1-10
    required: boolean;
    timeout: number; // milliseconds
}

export interface MultiStageChallenge {
    id: string;
    stages: ChallengeStage[];
    currentStage: number;
    completedStages: number[];
    riskLevel: 'low' | 'medium' | 'high' | 'critical';
    createdAt: number;
    expiresAt: number;
}

export interface StageResult {
    passed: boolean;
    nextStage: ChallengeStage | null;
    completed: boolean;
    message: string;
}

const challengeStore = new Map<string, MultiStageChallenge>();

// Challenge configurations by risk level
const CHALLENGE_CONFIGS: Record<string, ChallengeStage[]> = {
    low: [
        { type: 'honeypot', difficulty: 1, required: true, timeout: 60000 },
        { type: 'behavioral', difficulty: 2, required: false, timeout: 30000 },
    ],
    medium: [
        { type: 'pow', difficulty: 3, required: true, timeout: 30000 },
        { type: 'honeypot', difficulty: 2, required: true, timeout: 60000 },
        { type: 'text_captcha', difficulty: 4, required: true, timeout: 120000 },
    ],
    high: [
        { type: 'pow', difficulty: 5, required: true, timeout: 45000 },
        { type: 'honeypot', difficulty: 3, required: true, timeout: 60000 },
        { type: 'text_captcha', difficulty: 6, required: true, timeout: 120000 },
        { type: 'behavioral', difficulty: 5, required: true, timeout: 60000 },
    ],
    critical: [
        { type: 'pow', difficulty: 7, required: true, timeout: 60000 },
        { type: 'honeypot', difficulty: 4, required: true, timeout: 60000 },
        { type: 'image_captcha', difficulty: 8, required: true, timeout: 180000 },
        { type: 'text_captcha', difficulty: 7, required: true, timeout: 120000 },
        { type: 'behavioral', difficulty: 7, required: true, timeout: 90000 },
    ],
};

export class MultiStageChallengeSystem {

    /**
     * Create a multi-stage challenge based on risk level
     */
    static createChallenge(
        riskLevel: 'low' | 'medium' | 'high' | 'critical'
    ): MultiStageChallenge {
        const id = crypto.randomBytes(16).toString('hex');
        const stages = [...CHALLENGE_CONFIGS[riskLevel]];
        const createdAt = Date.now();

        // Calculate total timeout
        const totalTimeout = stages.reduce((sum, s) => sum + s.timeout, 0);

        const challenge: MultiStageChallenge = {
            id,
            stages,
            currentStage: 0,
            completedStages: [],
            riskLevel,
            createdAt,
            expiresAt: createdAt + totalTimeout,
        };

        challengeStore.set(id, challenge);
        this.cleanupExpired();

        return challenge;
    }

    /**
     * Get current stage for a challenge
     */
    static getCurrentStage(challengeId: string): ChallengeStage | null {
        const challenge = challengeStore.get(challengeId);
        if (!challenge) return null;
        if (Date.now() > challenge.expiresAt) {
            challengeStore.delete(challengeId);
            return null;
        }
        if (challenge.currentStage >= challenge.stages.length) return null;
        return challenge.stages[challenge.currentStage];
    }

    /**
     * Complete a stage and advance to next
     */
    static completeStage(challengeId: string, stagePassed: boolean): StageResult {
        const challenge = challengeStore.get(challengeId);

        if (!challenge) {
            return {
                passed: false,
                nextStage: null,
                completed: false,
                message: 'Challenge not found or expired',
            };
        }

        if (Date.now() > challenge.expiresAt) {
            challengeStore.delete(challengeId);
            return {
                passed: false,
                nextStage: null,
                completed: false,
                message: 'Challenge expired',
            };
        }

        const currentStage = challenge.stages[challenge.currentStage];

        if (!stagePassed && currentStage.required) {
            challengeStore.delete(challengeId);
            return {
                passed: false,
                nextStage: null,
                completed: false,
                message: 'Required stage failed',
            };
        }

        if (stagePassed) {
            challenge.completedStages.push(challenge.currentStage);
        }

        challenge.currentStage++;

        // Check if all stages completed
        if (challenge.currentStage >= challenge.stages.length) {
            challengeStore.delete(challengeId);
            return {
                passed: true,
                nextStage: null,
                completed: true,
                message: 'All challenges completed successfully',
            };
        }

        // Return next stage
        return {
            passed: stagePassed,
            nextStage: challenge.stages[challenge.currentStage],
            completed: false,
            message: 'Proceed to next stage',
        };
    }

    /**
     * Get challenge status
     */
    static getStatus(challengeId: string) {
        const challenge = challengeStore.get(challengeId);
        if (!challenge) return null;

        return {
            id: challenge.id,
            riskLevel: challenge.riskLevel,
            currentStage: challenge.currentStage,
            totalStages: challenge.stages.length,
            completedStages: challenge.completedStages.length,
            timeRemaining: challenge.expiresAt - Date.now(),
            isExpired: Date.now() > challenge.expiresAt,
        };
    }

    /**
     * Escalate challenge difficulty mid-session
     */
    static escalate(challengeId: string): MultiStageChallenge | null {
        const challenge = challengeStore.get(challengeId);
        if (!challenge) return null;

        // Increase difficulty of remaining stages
        for (let i = challenge.currentStage; i < challenge.stages.length; i++) {
            challenge.stages[i].difficulty = Math.min(10, challenge.stages[i].difficulty + 2);
        }

        // Add extra stage if not critical
        if (challenge.riskLevel !== 'critical') {
            challenge.stages.push({
                type: 'image_captcha',
                difficulty: 7,
                required: true,
                timeout: 180000,
            });
            challenge.expiresAt += 180000;
        }

        return challenge;
    }

    private static cleanupExpired(): void {
        const now = Date.now();
        for (const [id, challenge] of challengeStore.entries()) {
            if (now > challenge.expiresAt) {
                challengeStore.delete(id);
            }
        }
    }
}
