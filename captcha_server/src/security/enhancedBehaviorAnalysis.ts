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
        metadata: { totalTime: number; focusLostCount?: number; scrollEvents?: { y: number; timestamp: number }[] }
    ): BehaviorScore {
        const flags: string[] = [];
        let suspicionScore = 0;

        const metrics: Partial<BehaviorMetrics> = {
            mouseMovements: mouseEvents.filter(e => e.type === 'move').length,
            clicks: mouseEvents.filter(e => e.type === 'click').length,
            keystrokes: keyboardEvents.length,
            totalTime: metadata.totalTime,
            focusLostCount: metadata.focusLostCount || 0,
            scrollEvents: metadata.scrollEvents?.length || 0,
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

        // ===== Phase C: Keystroke Timing Analysis =====
        if (keyboardEvents.length >= 4) {
            const keystrokeAnalysis = this.analyzeKeystrokeTiming(keyboardEvents);
            metrics.avgKeypressTime = keystrokeAnalysis.avgKeypressTime;
            metrics.typingSpeed = keystrokeAnalysis.typingSpeed;
            metrics.typingRhythmVariance = keystrokeAnalysis.rhythmVariance;

            // Check for bot-like typing patterns
            if (keystrokeAnalysis.rhythmVariance < 5) {
                flags.push('Machine-like typing rhythm');
                suspicionScore += 25;
            }

            if (keystrokeAnalysis.avgKeypressTime < 20) {
                flags.push('Superhuman keypress speed');
                suspicionScore += 30;
            }

            if (keystrokeAnalysis.typingSpeed > 200) { // > 200 WPM
                flags.push('Superhuman typing speed');
                suspicionScore += 35;
            }

            // Check for simultaneous key events (bots often fire all at once)
            const simultaneousKeys = this.countSimultaneousKeys(keyboardEvents);
            if (simultaneousKeys > 2) {
                flags.push('Simultaneous key events detected');
                suspicionScore += 20;
            }
        }

        // ===== Phase C: Scroll Pattern Analysis =====
        if (metadata.scrollEvents && metadata.scrollEvents.length >= 3) {
            const scrollAnalysis = this.analyzeScrollPatterns(metadata.scrollEvents);
            metrics.scrollVariance = scrollAnalysis.variance;

            if (scrollAnalysis.variance < 10) {
                flags.push('Uniform scroll behavior');
                suspicionScore += 15;
            }

            if (scrollAnalysis.avgSpeed > 5000) { // pixels per second
                flags.push('Superhuman scroll speed');
                suspicionScore += 20;
            }
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

        // ===== Phase C: Calculate Overall Entropy Score =====
        const entropyScore = this.calculateEntropyScore(mouseEvents, keyboardEvents, metadata);
        if (entropyScore < 20) {
            flags.push('Low behavioral entropy');
            suspicionScore += 20;
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

    /**
     * Phase C: Analyze keystroke timing patterns
     */
    private static analyzeKeystrokeTiming(events: KeyboardEvent[]): {
        avgKeypressTime: number;
        typingSpeed: number;
        rhythmVariance: number;
    } {
        const intervals: number[] = [];
        const keyPressDurations: number[] = [];
        const keyMap = new Map<string, number>();

        for (const event of events) {
            if (event.type === 'down') {
                keyMap.set(event.key, event.timestamp);
            } else if (event.type === 'up') {
                const downTime = keyMap.get(event.key);
                if (downTime) {
                    keyPressDurations.push(event.timestamp - downTime);
                    keyMap.delete(event.key);
                }
            }
        }

        // Calculate intervals between keystrokes
        const downEvents = events.filter(e => e.type === 'down');
        for (let i = 1; i < downEvents.length; i++) {
            intervals.push(downEvents[i].timestamp - downEvents[i - 1].timestamp);
        }

        const avgKeypressTime = keyPressDurations.length > 0
            ? keyPressDurations.reduce((a, b) => a + b, 0) / keyPressDurations.length
            : 0;

        const avgInterval = intervals.length > 0
            ? intervals.reduce((a, b) => a + b, 0) / intervals.length
            : 0;

        // Words per minute (assuming 5 chars per word)
        const typingSpeed = avgInterval > 0 ? (60000 / avgInterval) / 5 : 0;

        const rhythmVariance = this.calculateVariance(intervals);

        return { avgKeypressTime, typingSpeed, rhythmVariance };
    }

    /**
     * Phase C: Detect simultaneous key events
     */
    private static countSimultaneousKeys(events: KeyboardEvent[]): number {
        const windowMs = 5; // 5ms window
        let simultaneousCount = 0;

        for (let i = 1; i < events.length; i++) {
            if (Math.abs(events[i].timestamp - events[i - 1].timestamp) < windowMs) {
                simultaneousCount++;
            }
        }

        return simultaneousCount;
    }

    /**
     * Phase C: Analyze scroll patterns
     */
    private static analyzeScrollPatterns(scrollEvents: { y: number; timestamp: number }[]): {
        variance: number;
        avgSpeed: number;
    } {
        const speeds: number[] = [];
        const deltaYs: number[] = [];

        for (let i = 1; i < scrollEvents.length; i++) {
            const dy = Math.abs(scrollEvents[i].y - scrollEvents[i - 1].y);
            const dt = scrollEvents[i].timestamp - scrollEvents[i - 1].timestamp;

            deltaYs.push(dy);
            if (dt > 0) {
                speeds.push(dy / dt * 1000); // pixels per second
            }
        }

        return {
            variance: this.calculateVariance(deltaYs),
            avgSpeed: speeds.length > 0 ? speeds.reduce((a, b) => a + b, 0) / speeds.length : 0,
        };
    }

    /**
     * Phase C: Calculate overall behavioral entropy
     */
    private static calculateEntropyScore(
        mouseEvents: MouseEvent[],
        keyboardEvents: KeyboardEvent[],
        metadata: { totalTime: number; scrollEvents?: { y: number; timestamp: number }[] }
    ): number {
        let entropy = 0;

        // More events = higher entropy
        entropy += Math.min(mouseEvents.length / 10, 20);
        entropy += Math.min(keyboardEvents.length / 5, 20);
        entropy += Math.min((metadata.scrollEvents?.length || 0) / 3, 10);

        // Time spent adds entropy
        entropy += Math.min(metadata.totalTime / 1000, 20);

        // Variety in event types
        const eventTypes = new Set([
            ...mouseEvents.map(e => e.type),
            ...keyboardEvents.map(e => e.type),
        ]);
        entropy += eventTypes.size * 5;

        // Position variety adds entropy
        if (mouseEvents.length > 0) {
            const uniquePositions = new Set(mouseEvents.map(e => `${Math.floor(e.x / 50)},${Math.floor(e.y / 50)}`));
            entropy += Math.min(uniquePositions.size * 2, 10);
        }

        return Math.min(entropy, 100);
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
