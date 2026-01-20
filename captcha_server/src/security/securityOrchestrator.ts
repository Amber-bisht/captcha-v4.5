/**
 * Ultimate Security Orchestrator - 100X Protection
 * Master controller combining ALL security systems
 */

import { AdvancedBotDetector, BotDetectionResult, ClientBotSignals } from './advancedBotDetection';
import { AdvancedFingerprintAnalyzer, AdvancedFingerprint, FingerprintAnalysis } from './advancedFingerprinting';
import { ProofOfWorkSystem, PoWChallenge, PoWSolution } from './proofOfWork';
import { HoneypotSystem, HoneypotChallenge, HoneypotResult } from './honeypot';
import { TLSFingerprintAnalyzer, TLSFingerprint, TLSAnalysisResult } from './tlsFingerprint';
import { EnhancedBehaviorAnalyzer, MouseEvent, KeyboardEvent, BehaviorScore } from './enhancedBehaviorAnalysis';
import { MultiStageChallengeSystem, MultiStageChallenge, StageResult } from './multiStageChallenge';
import { VPNProxyDetector, IPAnalysisResult, IPReputationService } from './vpnProxyDetector';
import { RequestAnomalyDetector, AnomalyResult, RequestSignature } from './requestAnomalyDetector';
import { deviceReputation, DeviceReputationResult } from './deviceReputation';
import { RequestIntegritySystem, TamperDetector } from './requestIntegrity';
import { InvisibleChallengeSystem, EnvironmentDetector } from './invisibleChallenge';

export interface SecurityContext {
    ip: string;
    userAgent: string;
    headers: Record<string, string | string[] | undefined>;
    clientSignals?: ClientBotSignals;
    fingerprint?: Partial<AdvancedFingerprint>;
    tlsFingerprint?: TLSFingerprint;
    behaviorData?: {
        mouseEvents: MouseEvent[];
        keyboardEvents: KeyboardEvent[];
        totalTime: number;
        focusLostCount?: number;
    };
    asnInfo?: { asn?: string; org?: string; isp?: string };
    body?: any;
    query?: any;
}

export interface UltimateSecurityAssessment {
    // Overall verdict
    overallRiskLevel: 'low' | 'medium' | 'high' | 'critical';
    overallScore: number; // 0-100, higher = more suspicious
    isBlocked: boolean;
    blockReason?: string;
    recommendation: 'allow' | 'challenge' | 'escalate' | 'block' | 'shadowban';

    // Challenge requirements
    requiredChallenges: string[];
    challengeDifficulty: number; // 1-10

    // Individual assessments
    botDetection?: BotDetectionResult;
    fingerprintAnalysis?: FingerprintAnalysis;
    tlsAnalysis?: TLSAnalysisResult;
    behaviorScore?: BehaviorScore;
    vpnProxyAnalysis?: IPAnalysisResult;
    anomalyResult?: AnomalyResult;
    deviceReputation?: DeviceReputationResult;
    tamperDetection?: { tampered: boolean; indicators: string[] };

    // Action items
    actions: string[];

    // Audit log
    auditLog: string[];
}

export interface ChallengeSuite {
    multiStage: MultiStageChallenge;
    honeypot: HoneypotChallenge;
    pow?: PoWChallenge;
    invisible?: any;
}

export class UltimateSecurityOrchestrator {
    private powSystem: ProofOfWorkSystem;
    private honeypotSystem: HoneypotSystem;
    private vpnDetector: VPNProxyDetector;
    private anomalyDetector: RequestAnomalyDetector;
    private integritySystem: RequestIntegritySystem;
    private invisibleChallengeSystem: InvisibleChallengeSystem;
    private ipReputationService: IPReputationService;

    constructor() {
        this.powSystem = new ProofOfWorkSystem();
        this.honeypotSystem = new HoneypotSystem();
        this.vpnDetector = new VPNProxyDetector();
        this.anomalyDetector = new RequestAnomalyDetector();
        this.integritySystem = new RequestIntegritySystem();
        this.invisibleChallengeSystem = new InvisibleChallengeSystem();
        this.ipReputationService = new IPReputationService();
    }

    /**
     * Perform ULTIMATE security assessment
     */
    async assess(context: SecurityContext): Promise<UltimateSecurityAssessment> {
        const auditLog: string[] = [];
        const actions: string[] = [];
        let totalScore = 0;
        let components = 0;

        auditLog.push(`[${new Date().toISOString()}] Security assessment started for IP: ${context.ip}`);

        const results: Partial<UltimateSecurityAssessment> = {
            requiredChallenges: [],
        };

        // ========== LAYER 1: Request Integrity ==========
        if (context.body || context.query) {
            results.tamperDetection = TamperDetector.analyze({
                headers: context.headers as Record<string, string | string[] | undefined>,
                body: context.body,
                query: context.query,
            });

            if (results.tamperDetection.tampered) {
                auditLog.push(`[TAMPER] Tampering detected: ${results.tamperDetection.indicators.join(', ')}`);
                totalScore += 50;
                actions.push('Log tampering attempt');
            }
        }

        // ========== LAYER 2: VPN/Proxy/Datacenter Detection ==========
        results.vpnProxyAnalysis = await this.vpnDetector.analyze(context.ip, context.asnInfo);

        if (results.vpnProxyAnalysis.isVPN) {
            auditLog.push(`[VPN] VPN detected: ${results.vpnProxyAnalysis.flags.join(', ')}`);
            totalScore += 25;
            actions.push('Require additional verification for VPN');
        }
        if (results.vpnProxyAnalysis.isProxy) {
            auditLog.push(`[PROXY] Proxy detected`);
            totalScore += 30;
        }
        if (results.vpnProxyAnalysis.isDatacenter) {
            auditLog.push(`[DATACENTER] Datacenter IP detected`);
            totalScore += 35;
            actions.push('Escalate challenge difficulty');
        }
        if (results.vpnProxyAnalysis.isTor) {
            auditLog.push(`[TOR] Tor exit node detected`);
            totalScore += 45;
            actions.push('Block or require maximum verification');
        }
        components++;

        // ========== LAYER 3: Bot Detection (Server-side) ==========
        const serverBotResult = AdvancedBotDetector.analyzeServerSignals(
            context.userAgent,
            context.headers
        );
        auditLog.push(`[BOT-SERVER] Confidence: ${serverBotResult.confidence}%, Risk: ${serverBotResult.riskLevel}`);

        // ========== LAYER 4: Bot Detection (Client-side) ==========
        let combinedBotResult = serverBotResult;
        if (context.clientSignals) {
            const clientBotResult = AdvancedBotDetector.analyzeClientSignals(context.clientSignals);
            combinedBotResult = AdvancedBotDetector.combineResults(clientBotResult, serverBotResult);
            auditLog.push(`[BOT-CLIENT] Combined confidence: ${combinedBotResult.confidence}%`);
        }
        results.botDetection = combinedBotResult;
        totalScore += combinedBotResult.confidence * 0.8;
        components++;

        // ========== LAYER 5: Advanced Fingerprint Analysis ==========
        if (context.fingerprint) {
            results.fingerprintAnalysis = AdvancedFingerprintAnalyzer.analyze(context.fingerprint);
            const fpScore = 100 - results.fingerprintAnalysis.consistencyScore;
            totalScore += fpScore * 0.5;
            components++;

            if (results.fingerprintAnalysis.suspiciousSignals.length > 0) {
                auditLog.push(`[FINGERPRINT] Suspicious: ${results.fingerprintAnalysis.suspiciousSignals.join(', ')}`);
            }
        }

        // ========== LAYER 6: TLS Fingerprint Analysis ==========
        if (context.tlsFingerprint) {
            results.tlsAnalysis = TLSFingerprintAnalyzer.analyze(context.tlsFingerprint);
            if (results.tlsAnalysis.isKnownBot) {
                totalScore += results.tlsAnalysis.confidence;
                auditLog.push(`[TLS] Known bot signature: ${results.tlsAnalysis.matchedSignature}`);
                actions.push('Block known bot TLS signature');
            }
            components++;
        }

        // ========== LAYER 7: Behavior Analysis ==========
        if (context.behaviorData) {
            results.behaviorScore = EnhancedBehaviorAnalyzer.analyze(
                context.behaviorData.mouseEvents,
                context.behaviorData.keyboardEvents,
                {
                    totalTime: context.behaviorData.totalTime,
                    focusLostCount: context.behaviorData.focusLostCount,
                }
            );
            totalScore += results.behaviorScore.score * 0.6;
            components++;

            if (results.behaviorScore.flags.length > 0) {
                auditLog.push(`[BEHAVIOR] Flags: ${results.behaviorScore.flags.join(', ')}`);
            }
        }

        // ========== LAYER 8: Request Anomaly Detection ==========
        const fingerprintHash = context.fingerprint
            ? AdvancedFingerprintAnalyzer.generateHash(context.fingerprint)
            : 'unknown';

        const requestSig: RequestSignature = {
            ip: context.ip,
            fingerprint: fingerprintHash,
            userAgent: context.userAgent,
            timestamp: Date.now(),
            endpoint: 'captcha',
            success: false, // Will be updated after verification
        };

        results.anomalyResult = this.anomalyDetector.recordAndAnalyze(requestSig);
        if (results.anomalyResult.isAnomaly) {
            totalScore += results.anomalyResult.anomalyScore * 0.7;
            auditLog.push(`[ANOMALY] Types: ${results.anomalyResult.anomalyType.join(', ')}`);
            actions.push(`Recommended action: ${results.anomalyResult.recommendation}`);
        }
        components++;

        // ========== LAYER 9: Device Reputation ==========
        results.deviceReputation = deviceReputation.evaluate(fingerprintHash);
        if (results.deviceReputation.isBanned) {
            totalScore = 100;
            auditLog.push(`[REPUTATION] Device is BANNED: ${results.deviceReputation.banReason}`);
            actions.push('Block banned device');
        } else {
            const repPenalty = (100 - results.deviceReputation.reputationScore) * 0.3;
            totalScore += repPenalty;
            auditLog.push(`[REPUTATION] Score: ${results.deviceReputation.reputationScore}, Level: ${results.deviceReputation.reputationLevel}`);
        }
        components++;

        // ========== CALCULATE FINAL SCORE ==========
        const overallScore = Math.min(Math.round(totalScore / Math.max(components, 1)), 100);

        // Determine risk level
        let overallRiskLevel: 'low' | 'medium' | 'high' | 'critical';
        if (overallScore >= 70) {
            overallRiskLevel = 'critical';
        } else if (overallScore >= 50) {
            overallRiskLevel = 'high';
        } else if (overallScore >= 25) {
            overallRiskLevel = 'medium';
        } else {
            overallRiskLevel = 'low';
        }

        // Determine if blocked
        let isBlocked = false;
        let blockReason: string | undefined;

        if (results.deviceReputation?.isBanned) {
            isBlocked = true;
            blockReason = `Device banned: ${results.deviceReputation.banReason}`;
        } else if (overallScore >= 90) {
            isBlocked = true;
            blockReason = 'Extreme risk score';
        } else if (combinedBotResult.isBot && combinedBotResult.confidence >= 85) {
            isBlocked = true;
            blockReason = 'High-confidence bot detection';
        } else if (results.tlsAnalysis?.isKnownBot) {
            isBlocked = true;
            blockReason = `Known bot TLS: ${results.tlsAnalysis.matchedSignature}`;
        } else if (results.vpnProxyAnalysis?.isTor && overallScore >= 50) {
            isBlocked = true;
            blockReason = 'Tor with suspicious activity';
        } else if (results.tamperDetection?.tampered) {
            isBlocked = true;
            blockReason = 'Request tampering detected';
        }

        // Determine recommendation
        let recommendation: 'allow' | 'challenge' | 'escalate' | 'block' | 'shadowban';
        if (isBlocked) {
            recommendation = 'block';
        } else if (results.anomalyResult?.recommendation === 'shadowban') {
            recommendation = 'shadowban';
        } else if (overallScore >= 60) {
            recommendation = 'escalate';
        } else if (overallScore >= 30) {
            recommendation = 'challenge';
        } else {
            recommendation = 'allow';
        }

        // Determine required challenges
        const requiredChallenges = this.getRequiredChallenges(overallRiskLevel, results);

        // Calculate challenge difficulty
        const baseDifficulty = { low: 2, medium: 4, high: 6, critical: 8 }[overallRiskLevel];
        const challengeDifficulty = Math.min(10, baseDifficulty +
            (results.deviceReputation?.challengeMultiplier || 1) - 1);

        auditLog.push(`[FINAL] Risk: ${overallRiskLevel}, Score: ${overallScore}, Recommendation: ${recommendation}`);

        return {
            overallRiskLevel,
            overallScore,
            isBlocked,
            blockReason,
            recommendation,
            requiredChallenges,
            challengeDifficulty,
            botDetection: results.botDetection,
            fingerprintAnalysis: results.fingerprintAnalysis,
            tlsAnalysis: results.tlsAnalysis,
            behaviorScore: results.behaviorScore,
            vpnProxyAnalysis: results.vpnProxyAnalysis,
            anomalyResult: results.anomalyResult,
            deviceReputation: results.deviceReputation,
            tamperDetection: results.tamperDetection,
            actions,
            auditLog,
        };
    }

    /**
     * Generate comprehensive challenge suite
     */
    generateChallenges(assessment: UltimateSecurityAssessment): ChallengeSuite {
        const riskLevel = assessment.overallRiskLevel;

        // Multi-stage challenge
        const multiStage = MultiStageChallengeSystem.createChallenge(riskLevel);

        // Honeypot with more fields for high risk
        const honeypotFields = { low: 2, medium: 3, high: 4, critical: 5 }[riskLevel];
        const honeypot = this.honeypotSystem.generateChallenge(honeypotFields);

        // PoW with difficulty based on risk
        let pow: PoWChallenge | undefined;
        if (riskLevel !== 'low') {
            pow = this.powSystem.generateChallenge(riskLevel);
        }

        // Invisible challenge for high risk
        let invisible: any;
        if (riskLevel === 'high' || riskLevel === 'critical') {
            invisible = this.invisibleChallengeSystem.generateChallenge(assessment.challengeDifficulty);
        }

        return { multiStage, honeypot, pow, invisible };
    }

    /**
     * Record challenge result for device reputation
     */
    recordChallengeResult(
        fingerprintHash: string,
        success: boolean,
        ip: string,
        suspicious?: { type: string; details: string; severity: 'low' | 'medium' | 'high' }
    ): void {
        deviceReputation.recordChallengeAttempt(fingerprintHash, success, ip, suspicious);
    }

    /**
     * Verify PoW solution
     */
    verifyPoW(solution: PoWSolution, computeTime?: number) {
        return this.powSystem.verifySolution(solution, computeTime);
    }

    /**
     * Verify honeypot
     */
    verifyHoneypot(challengeId: string, fields: Record<string, string>): HoneypotResult {
        return this.honeypotSystem.verify(challengeId, fields);
    }

    /**
     * Verify invisible challenge
     */
    verifyInvisibleChallenge(challengeId: string, answers: any) {
        return this.invisibleChallengeSystem.verifyChallenge(challengeId, answers);
    }

    /**
     * Complete a multi-stage challenge step
     */
    completeStage(challengeId: string, passed: boolean): StageResult {
        return MultiStageChallengeSystem.completeStage(challengeId, passed);
    }

    /**
     * Add IP reputation provider
     */
    addIPReputationProvider(name: string, apiKey: string): void {
        this.ipReputationService.addProvider(name, apiKey);
    }

    private getRequiredChallenges(
        riskLevel: string,
        results: Partial<UltimateSecurityAssessment>
    ): string[] {
        const challenges: string[] = [];

        switch (riskLevel) {
            case 'low':
                challenges.push('honeypot');
                break;
            case 'medium':
                challenges.push('pow', 'honeypot', 'captcha');
                break;
            case 'high':
                challenges.push('pow', 'honeypot', 'captcha', 'invisible', 'behavior');
                break;
            case 'critical':
                challenges.push('pow', 'honeypot', 'image_captcha', 'text_captcha', 'invisible', 'behavior', 'audio_captcha');
                break;
        }

        // Add extra challenges based on specific detections
        if (results.vpnProxyAnalysis?.isDatacenter) {
            if (!challenges.includes('invisible')) challenges.push('invisible');
        }

        if (results.vpnProxyAnalysis?.isVPN) {
            if (!challenges.includes('pow')) challenges.push('pow');
        }

        return challenges;
    }
}

// Export singleton instance
export const ultimateSecurityOrchestrator = new UltimateSecurityOrchestrator();

// Also export the old name for backwards compatibility
export const securityOrchestrator = ultimateSecurityOrchestrator;
