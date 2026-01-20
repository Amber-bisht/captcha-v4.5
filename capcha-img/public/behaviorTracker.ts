/**
 * Client-side behavior tracking
 */

type BehaviorEventType = 'mousemove' | 'click' | 'keypress' | 'scroll' | 'focus';

interface BehaviorEvent {
  type: BehaviorEventType;
  timestamp: number;
  coordinates?: {
    x: number;
    y: number;
  };
  timing?: number;
  target?: string;
}

interface BehaviorData {
  events: BehaviorEvent[];
  totalTime: number;
  mouseMovements: number;
  clicks: number;
  averageSpeed?: number;
}

class BehaviorTracker {
  private events: BehaviorEvent[] = [];
  private startTime: number = Date.now();
  private mouseMovements: number = 0;
  private clicks: number = 0;
  private lastMousePosition: { x: number; y: number } | null = null;

  constructor() {
    this.initializeTracking();
  }

  /**
   * Initialize event listeners
   */
  private initializeTracking(): void {
    // Mouse move tracking
    document.addEventListener('mousemove', (e) => {
      this.trackEvent('mousemove', {
        x: e.clientX,
        y: e.clientY,
      });
      this.mouseMovements++;
      this.lastMousePosition = { x: e.clientX, y: e.clientY };
    });

    // Click tracking
    document.addEventListener('click', (e) => {
      this.trackEvent('click', {
        x: e.clientX,
        y: e.clientY,
      });
      this.clicks++;
    });

    // Keypress tracking
    document.addEventListener('keypress', () => {
      this.trackEvent('keypress');
    });

    // Scroll tracking
    document.addEventListener('scroll', () => {
      this.trackEvent('scroll');
    });

    // Focus tracking
    window.addEventListener('focus', () => {
      this.trackEvent('focus');
    });
  }

  /**
   * Track an event
   */
  private trackEvent(
    type: BehaviorEventType,
    coordinates?: { x: number; y: number }
  ): void {
    const now = Date.now();
    const lastEvent = this.events[this.events.length - 1];
    const timing = lastEvent ? now - lastEvent.timestamp : 0;

    this.events.push({
      type,
      timestamp: now,
      coordinates,
      timing,
    });
  }

  /**
   * Calculate average mouse speed
   */
  private calculateAverageSpeed(): number {
    if (this.events.length < 2) return 0;

    let totalDistance = 0;
    let totalTime = 0;

    for (let i = 1; i < this.events.length; i++) {
      const prev = this.events[i - 1];
      const curr = this.events[i];

      if (
        prev.coordinates &&
        curr.coordinates &&
        prev.type === 'mousemove' &&
        curr.type === 'mousemove'
      ) {
        const distance = Math.sqrt(
          Math.pow(curr.coordinates.x - prev.coordinates.x, 2) +
            Math.pow(curr.coordinates.y - prev.coordinates.y, 2)
        );
        const time = curr.timestamp - prev.timestamp;

        if (time > 0) {
          totalDistance += distance;
          totalTime += time;
        }
      }
    }

    return totalTime > 0 ? totalDistance / totalTime : 0;
  }

  /**
   * Get behavior data
   */
  getBehaviorData(): BehaviorData {
    const totalTime = Date.now() - this.startTime;
    const averageSpeed = this.calculateAverageSpeed();

    return {
      events: this.events,
      totalTime,
      mouseMovements: this.mouseMovements,
      clicks: this.clicks,
      averageSpeed,
    };
  }

  /**
   * Reset tracker
   */
  reset(): void {
    this.events = [];
    this.startTime = Date.now();
    this.mouseMovements = 0;
    this.clicks = 0;
    this.lastMousePosition = null;
  }
}

// Export singleton instance
const behaviorTracker = new BehaviorTracker();

// Export function to get behavior data
function getBehaviorData(): BehaviorData {
  return behaviorTracker.getBehaviorData();
}

// Make available globally
(window as any).getBehaviorData = getBehaviorData;
