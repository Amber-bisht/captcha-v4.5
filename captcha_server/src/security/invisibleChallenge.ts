/**
 * Invisible Challenge System
 * Challenges that only real browsers can solve
 */

import crypto from 'crypto';

export interface InvisibleChallenge {
    id: string;
    type: 'math' | 'timing' | 'dom' | 'crypto' | 'behavior' | 'composite';
    challenge: any;
    expectedAnswer: string;
    createdAt: number;
    expiresAt: number;
    difficulty: number;
}

export interface ChallengeResult {
    passed: boolean;
    score: number;
    details: string[];
}

const activeChallenges = new Map<string, InvisibleChallenge>();

export class InvisibleChallengeSystem {

    /**
     * Generate a composite invisible challenge
     */
    generateChallenge(difficulty: number = 3): InvisibleChallenge {
        const id = crypto.randomBytes(16).toString('hex');

        // Create multiple micro-challenges
        const microChallenges = {
            math: this.generateMathChallenge(),
            timing: this.generateTimingChallenge(),
            dom: this.generateDOMChallenge(),
            crypto: this.generateCryptoChallenge(),
        };

        const expectedAnswer = crypto
            .createHash('sha256')
            .update(Object.values(microChallenges).map(c => c.expected).join(':'))
            .digest('hex')
            .slice(0, 16);

        const challenge: InvisibleChallenge = {
            id,
            type: 'composite',
            challenge: microChallenges,
            expectedAnswer,
            createdAt: Date.now(),
            expiresAt: Date.now() + 120000, // 2 minutes
            difficulty,
        };

        activeChallenges.set(id, challenge);

        // Don't include expected answers in returned challenge
        return {
            ...challenge,
            expectedAnswer: '',
            challenge: {
                math: { expression: microChallenges.math.expression },
                timing: { minDelay: microChallenges.timing.minDelay, sequence: microChallenges.timing.sequence },
                dom: { selector: microChallenges.dom.selector, operation: microChallenges.dom.operation },
                crypto: { data: microChallenges.crypto.data, algorithm: microChallenges.crypto.algorithm },
            },
        };
    }

    /**
     * Verify challenge answers
     */
    verifyChallenge(
        challengeId: string,
        answers: { math?: string; timing?: number; dom?: string; crypto?: string }
    ): ChallengeResult {
        const challenge = activeChallenges.get(challengeId);

        if (!challenge) {
            return { passed: false, score: 0, details: ['Challenge not found or expired'] };
        }

        if (Date.now() > challenge.expiresAt) {
            activeChallenges.delete(challengeId);
            return { passed: false, score: 0, details: ['Challenge expired'] };
        }

        const details: string[] = [];
        let score = 0;
        const maxScore = 100;
        const pointsPerChallenge = 25;

        const microChallenges = challenge.challenge;

        // Verify math challenge
        if (answers.math === microChallenges.math.expected) {
            score += pointsPerChallenge;
            details.push('Math challenge: PASS');
        } else {
            details.push('Math challenge: FAIL');
        }

        // Verify timing challenge (must be within expected range)
        if (answers.timing !== undefined) {
            const minTime = microChallenges.timing.minDelay;
            const maxTime = minTime * 3;
            if (answers.timing >= minTime && answers.timing <= maxTime) {
                score += pointsPerChallenge;
                details.push('Timing challenge: PASS');
            } else {
                details.push(`Timing challenge: FAIL (${answers.timing}ms, expected ${minTime}-${maxTime}ms)`);
            }
        }

        // Verify DOM challenge
        if (answers.dom === microChallenges.dom.expected) {
            score += pointsPerChallenge;
            details.push('DOM challenge: PASS');
        } else {
            details.push('DOM challenge: FAIL');
        }

        // Verify crypto challenge
        if (answers.crypto === microChallenges.crypto.expected) {
            score += pointsPerChallenge;
            details.push('Crypto challenge: PASS');
        } else {
            details.push('Crypto challenge: FAIL');
        }

        // Delete challenge after verification
        activeChallenges.delete(challengeId);

        const passed = score >= 75; // Need 3 out of 4 challenges

        return { passed, score, details };
    }

    /**
     * Generate client-side code for solving challenges
     */
    generateClientScript(challenge: InvisibleChallenge): string {
        return `
(async function() {
  const results = {};
  
  // Math challenge
  try {
    results.math = eval('${challenge.challenge.math.expression}').toString();
  } catch(e) { results.math = ''; }
  
  // Timing challenge
  const timingStart = performance.now();
  await new Promise(r => setTimeout(r, ${challenge.challenge.timing.minDelay}));
  results.timing = Math.round(performance.now() - timingStart);
  
  // DOM challenge
  try {
    const el = document.querySelector('${challenge.challenge.dom.selector}');
    if (el) {
      results.dom = el.${challenge.challenge.dom.operation};
    }
  } catch(e) { results.dom = ''; }
  
  // Crypto challenge
  try {
    const data = '${challenge.challenge.crypto.data}';
    const encoder = new TextEncoder();
    const hashBuffer = await crypto.subtle.digest('SHA-256', encoder.encode(data));
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    results.crypto = hashArray.map(b => b.toString(16).padStart(2, '0')).join('').slice(0, 16);
  } catch(e) { results.crypto = ''; }
  
  // Store results
  window.__invisibleChallengeResults = {
    id: '${challenge.id}',
    answers: results
  };
})();
`;
    }

    private generateMathChallenge(): { expression: string; expected: string } {
        const a = Math.floor(Math.random() * 100);
        const b = Math.floor(Math.random() * 100);
        const ops = ['+', '-', '*'];
        const op = ops[Math.floor(Math.random() * ops.length)];
        const expression = `${a}${op}${b}`;
        const expected = eval(expression).toString();
        return { expression, expected };
    }

    private generateTimingChallenge(): { minDelay: number; sequence: number[]; expected: number } {
        const minDelay = 100 + Math.floor(Math.random() * 200); // 100-300ms
        const sequence = [1, 2, 3].map(() => Math.floor(Math.random() * 100));
        return { minDelay, sequence, expected: minDelay };
    }

    private generateDOMChallenge(): { selector: string; operation: string; expected: string } {
        // Challenge requires DOM interaction
        return {
            selector: 'html',
            operation: 'lang || "en"',
            expected: 'en',
        };
    }

    private generateCryptoChallenge(): { data: string; algorithm: string; expected: string } {
        const data = crypto.randomBytes(16).toString('hex');
        const expected = crypto.createHash('sha256').update(data).digest('hex').slice(0, 16);
        return { data, algorithm: 'sha256', expected };
    }
}

/**
 * Environment Fingerprinting
 * Detect headless/automated environments
 */
export class EnvironmentDetector {
    /**
     * Generate detection script
     */
    static generateDetectionScript(): string {
        return `
(function() {
  const signals = {
    // Navigator checks
    webdriver: !!navigator.webdriver,
    languages: navigator.languages?.length || 0,
    plugins: navigator.plugins?.length || 0,
    platform: navigator.platform,
    hardwareConcurrency: navigator.hardwareConcurrency || 0,
    deviceMemory: navigator.deviceMemory || 0,
    
    // Window checks
    outerWidth: window.outerWidth,
    outerHeight: window.outerHeight,
    chrome: !!window.chrome,
    
    // Document checks
    documentFocus: document.hasFocus(),
    hidden: document.hidden,
    
    // Timing checks
    performanceNow: typeof performance.now === 'function',
    
    // Canvas check
    canvasSupported: (function() {
      try {
        const c = document.createElement('canvas');
        return !!(c.getContext('2d'));
      } catch(e) { return false; }
    })(),
    
    // WebGL check
    webglSupported: (function() {
      try {
        const c = document.createElement('canvas');
        return !!(c.getContext('webgl') || c.getContext('experimental-webgl'));
      } catch(e) { return false; }
    })(),
    
    // Audio check
    audioSupported: typeof AudioContext !== 'undefined' || typeof webkitAudioContext !== 'undefined',
    
    // Permissions API
    permissionsSupported: 'permissions' in navigator,
    
    // Battery API (deprecated but useful)
    batterySupported: 'getBattery' in navigator,
    
    // Touch support
    touchSupported: 'ontouchstart' in window || navigator.maxTouchPoints > 0,
    
    // Notification permission
    notificationPermission: typeof Notification !== 'undefined' ? Notification.permission : 'unsupported',
    
    // Timezone
    timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
    
    // Screen
    colorDepth: screen.colorDepth,
    pixelDepth: screen.pixelDepth,
  };
  
  window.__envSignals = signals;
})();
`;
    }

    /**
     * Analyze environment signals
     */
    static analyzeSignals(signals: Record<string, any>): {
        isAutomated: boolean;
        confidence: number;
        indicators: string[];
    } {
        const indicators: string[] = [];
        let score = 0;

        if (signals.webdriver) {
            indicators.push('WebDriver detected');
            score += 50;
        }

        if (signals.plugins === 0 && signals.platform?.includes('Win')) {
            indicators.push('Windows with no plugins');
            score += 20;
        }

        if (signals.languages === 0) {
            indicators.push('No languages configured');
            score += 15;
        }

        if (signals.hardwareConcurrency === 0) {
            indicators.push('Hardware concurrency is 0');
            score += 25;
        }

        if (!signals.chrome && signals.platform?.includes('Win')) {
            indicators.push('Windows without chrome object');
            score += 15;
        }

        if (signals.outerWidth === signals.innerWidth && signals.outerHeight === signals.innerHeight) {
            indicators.push('No browser chrome (outer = inner dimensions)');
            score += 20;
        }

        if (!signals.canvasSupported) {
            indicators.push('Canvas not supported');
            score += 15;
        }

        if (!signals.webglSupported) {
            indicators.push('WebGL not supported');
            score += 15;
        }

        const confidence = Math.min(score, 100);

        return {
            isAutomated: confidence >= 40,
            confidence,
            indicators,
        };
    }
}
