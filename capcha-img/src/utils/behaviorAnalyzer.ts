import { BehaviorData, BehaviorScore, BehaviorEvent } from '../types/behavior';

export class BehaviorAnalyzer {
  /**
   * Analyze behavior data and calculate risk score
   */
  static analyzeBehavior(data: BehaviorData): BehaviorScore {
    const reasons: string[] = [];
    let score = 0;

    // Check minimum interaction time
    if (data.totalTime < 2000) {
      score += 30;
      reasons.push('Interaction time too short');
    }

    // Check mouse movement patterns
    if (data.mouseMovements < 10) {
      score += 20;
      reasons.push('Insufficient mouse movements');
    }

    // Check for uniform timing (bot-like)
    if (data.events.length > 2) {
      const timings = this.extractTimings(data.events);
      const variance = this.calculateVariance(timings);
      if (variance < 100) {
        score += 25;
        reasons.push('Uniform timing patterns detected');
      }
    }

    // Check for straight-line mouse movements (bot-like)
    const straightLineScore = this.checkStraightLineMovements(data.events);
    if (straightLineScore > 0.8) {
      score += 20;
      reasons.push('Unnatural mouse movement patterns');
    }

    // Check click patterns
    if (data.clicks < 2) {
      score += 15;
      reasons.push('Insufficient clicks');
    }

    // Check average speed
    if (data.averageSpeed && data.averageSpeed > 1000) {
      score += 10;
      reasons.push('Unusually fast interactions');
    }

    // Determine risk level
    let riskLevel: 'low' | 'medium' | 'high';
    if (score < 30) {
      riskLevel = 'low';
    } else if (score < 60) {
      riskLevel = 'medium';
    } else {
      riskLevel = 'high';
    }

    return {
      score: Math.min(score, 100),
      riskLevel,
      reasons,
    };
  }

  /**
   * Extract timing differences between events
   */
  private static extractTimings(events: BehaviorEvent[]): number[] {
    const timings: number[] = [];
    for (let i = 1; i < events.length; i++) {
      timings.push(events[i].timestamp - events[i - 1].timestamp);
    }
    return timings;
  }

  /**
   * Calculate variance of timing array
   */
  private static calculateVariance(values: number[]): number {
    if (values.length === 0) return 0;
    const mean = values.reduce((a, b) => a + b, 0) / values.length;
    const squaredDiffs = values.map((value) => Math.pow(value - mean, 2));
    return squaredDiffs.reduce((a, b) => a + b, 0) / values.length;
  }

  /**
   * Check for straight-line mouse movements
   */
  private static checkStraightLineMovements(events: BehaviorEvent[]): number {
    const mouseEvents = events.filter((e) => e.type === 'mousemove' && e.coordinates);
    if (mouseEvents.length < 3) return 0;

    let straightLineCount = 0;
    for (let i = 2; i < mouseEvents.length; i++) {
      const p1 = mouseEvents[i - 2].coordinates!;
      const p2 = mouseEvents[i - 1].coordinates!;
      const p3 = mouseEvents[i].coordinates!;

      // Check if three points are collinear
      const area =
        Math.abs(
          (p2.x - p1.x) * (p3.y - p1.y) - (p3.x - p1.x) * (p2.y - p1.y)
        ) / 2;
      if (area < 1) {
        straightLineCount++;
      }
    }

    return straightLineCount / (mouseEvents.length - 2);
  }

  /**
   * Detect headless browser indicators
   */
  static detectHeadlessBrowser(userAgent: string, headers: Record<string, string>): boolean {
    // Check for common headless browser indicators
    const headlessIndicators = [
      'headless',
      'phantom',
      'selenium',
      'webdriver',
      'puppeteer',
      'playwright',
    ];

    const uaLower = userAgent.toLowerCase();
    for (const indicator of headlessIndicators) {
      if (uaLower.includes(indicator)) {
        return true;
      }
    }

    // Check for missing common headers
    if (!headers['accept-language'] || !headers['accept-encoding']) {
      return true;
    }

    return false;
  }
}
