/**
 * Enhanced Behavior Analysis - ML-Ready Behavioral Scoring
 */

export interface MouseEvent {
    x: number;
    y: number;
    timestamp: number;
    type: 'move' | 'click' | 'scroll';
}

export interface KeyboardEvent {
    key: string;
    timestamp: number;
    type: 'down' | 'up';
}

export interface BehaviorMetrics {
    // Mouse metrics
    mouseMovements: number;
    totalDistance: number;
    avgSpeed: number;
    maxSpeed: number;
    accelerationChanges: number;
    straightLineRatio: number;
    curveComplexity: number;
    jitterScore: number;

    // Click metrics
    clicks: number;
    avgClickInterval: number;
    clickVariance: number;

    // Keyboard metrics
    keystrokes: number;
    avgKeypressTime: number;
    typingSpeed: number;
    typingRhythmVariance: number;

    // Timing
    totalTime: number;
    idleTime: number;
    focusLostCount: number;

    // Scroll
    scrollEvents: number;
    scrollVariance: number;
}

export interface BehaviorScore {
    score: number; // 0-100, higher = more suspicious
    humanProbability: number; // 0-100
    riskLevel: 'low' | 'medium' | 'high' | 'critical';
    flags: string[];
    metrics: Partial<BehaviorMetrics>;
}

export class EnhancedBehaviorAnalyzer {
    /**
     * Analyze behavior data and return ML-ready scoring
     */
    static analyze(
        mouseEvents: MouseEvent[],
        keyboardEvents: KeyboardEvent[],
        metadata: { totalTime: number; focusLostCount?: number }
    ): BehaviorScore {
        const flags: string[] = [];
        let suspicionScore = 0;

        const metrics: Partial<BehaviorMetrics> = {
            mouseMovements: mouseEvents.filter(e => e.type === 'move').length,
            clicks: mouseEvents.filter(e => e.type === 'click').length,
            keystrokes: keyboardEvents.length,
            totalTime: metadata.totalTime,
            focusLostCount: metadata.focusLostCount || 0,
        };

        // Calculate mouse metrics
        const movements = mouseEvents.filter(e => e.type === 'move');
        if (movements.length > 1) {
            const { distance, speeds, accelerations } = this.calculateMouseMetrics(movements);
            metrics.totalDistance = distance;
            metrics.avgSpeed = speeds.reduce((a, b) => a + b, 0) / speeds.length;
            metrics.maxSpeed = Math.max(...speeds);
            metrics.accelerationChanges = this.countDirectionChanges(accelerations);
            metrics.straightLineRatio = this.calculateStraightLineRatio(movements);
            metrics.curveComplexity = this.calculateCurveComplexity(movements);
            metrics.jitterScore = this.calculateJitter(movements);
        }

        // Analyze timing
        if (metadata.totalTime < 1000) {
            flags.push('Too fast: < 1 second');
            suspicionScore += 35;
        } else if (metadata.totalTime < 2000) {
            flags.push('Very fast: < 2 seconds');
            suspicionScore += 20;
        }

        // Analyze mouse patterns
        if (metrics.mouseMovements !== undefined && metrics.mouseMovements < 3) {
            flags.push('Minimal mouse movement');
            suspicionScore += 15;
        }

        if (metrics.straightLineRatio !== undefined && metrics.straightLineRatio > 0.85) {
            flags.push('Unnatural straight-line movements');
            suspicionScore += 25;
        }

        if (metrics.jitterScore !== undefined && metrics.jitterScore < 0.1) {
            flags.push('No natural mouse jitter');
            suspicionScore += 20;
        }

        if (metrics.avgSpeed !== undefined && metrics.avgSpeed > 2000) {
            flags.push('Superhuman mouse speed');
            suspicionScore += 30;
        }

        // Analyze timing uniformity
        if (movements.length > 5) {
            const intervals = this.extractIntervals(movements);
            const variance = this.calculateVariance(intervals);
            if (variance < 50) {
                flags.push('Suspiciously uniform timing');
                suspicionScore += 25;
            }
        }

        // Calculate final scores
        const score = Math.min(suspicionScore, 100);
        const humanProbability = Math.max(0, 100 - score);

        let riskLevel: 'low' | 'medium' | 'high' | 'critical';
        if (score >= 70) riskLevel = 'critical';
        else if (score >= 50) riskLevel = 'high';
        else if (score >= 25) riskLevel = 'medium';
        else riskLevel = 'low';

        return { score, humanProbability, riskLevel, flags, metrics };
    }

    private static calculateMouseMetrics(events: MouseEvent[]) {
        let distance = 0;
        const speeds: number[] = [];
        const accelerations: number[] = [];

        for (let i = 1; i < events.length; i++) {
            const dx = events[i].x - events[i - 1].x;
            const dy = events[i].y - events[i - 1].y;
            const d = Math.sqrt(dx * dx + dy * dy);
            const dt = events[i].timestamp - events[i - 1].timestamp;

            distance += d;
            if (dt > 0) {
                const speed = d / dt;
                speeds.push(speed);
                if (speeds.length > 1) {
                    accelerations.push(speed - speeds[speeds.length - 2]);
                }
            }
        }

        return { distance, speeds, accelerations };
    }

    private static countDirectionChanges(values: number[]): number {
        let changes = 0;
        for (let i = 1; i < values.length; i++) {
            if ((values[i] > 0) !== (values[i - 1] > 0)) changes++;
        }
        return changes;
    }

    private static calculateStraightLineRatio(events: MouseEvent[]): number {
        if (events.length < 3) return 0;
        let straightCount = 0;

        for (let i = 2; i < events.length; i++) {
            const area = Math.abs(
                (events[i - 1].x - events[i - 2].x) * (events[i].y - events[i - 2].y) -
                (events[i].x - events[i - 2].x) * (events[i - 1].y - events[i - 2].y)
            ) / 2;
            if (area < 5) straightCount++;
        }

        return straightCount / (events.length - 2);
    }

    private static calculateCurveComplexity(events: MouseEvent[]): number {
        if (events.length < 4) return 0;
        let complexity = 0;

        for (let i = 2; i < events.length; i++) {
            const angle1 = Math.atan2(
                events[i - 1].y - events[i - 2].y,
                events[i - 1].x - events[i - 2].x
            );
            const angle2 = Math.atan2(
                events[i].y - events[i - 1].y,
                events[i].x - events[i - 1].x
            );
            complexity += Math.abs(angle2 - angle1);
        }

        return complexity / events.length;
    }

    private static calculateJitter(events: MouseEvent[]): number {
        if (events.length < 5) return 0;
        let jitter = 0;

        for (let i = 1; i < events.length; i++) {
            const d = Math.sqrt(
                Math.pow(events[i].x - events[i - 1].x, 2) +
                Math.pow(events[i].y - events[i - 1].y, 2)
            );
            if (d < 3) jitter++;
        }

        return jitter / events.length;
    }

    private static extractIntervals(events: MouseEvent[]): number[] {
        const intervals: number[] = [];
        for (let i = 1; i < events.length; i++) {
            intervals.push(events[i].timestamp - events[i - 1].timestamp);
        }
        return intervals;
    }

    private static calculateVariance(values: number[]): number {
        if (values.length === 0) return 0;
        const mean = values.reduce((a, b) => a + b, 0) / values.length;
        const squaredDiffs = values.map(v => Math.pow(v - mean, 2));
        return squaredDiffs.reduce((a, b) => a + b, 0) / values.length;
    }
}
