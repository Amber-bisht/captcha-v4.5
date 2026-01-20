/**
 * Client-Side Enhanced Behavior Tracker
 * ML-ready behavioral data collection
 * Wrapped in IIFE to avoid global conflicts
 */

(function () {
    interface BehaviorMouseEvent {
        x: number;
        y: number;
        timestamp: number;
        type: 'move' | 'click' | 'scroll';
    }

    interface BehaviorKeyEvent {
        key: string;
        timestamp: number;
        type: 'down' | 'up';
    }

    interface BehaviorDataResult {
        mouseEvents: BehaviorMouseEvent[];
        keyboardEvents: BehaviorKeyEvent[];
        totalTime: number;
        focusLostCount: number;
        scrollEvents: number;
        pageVisibilityChanges: number;
    }

    class EnhancedBehaviorTracker {
        private mouseEvents: BehaviorMouseEvent[] = [];
        private keyboardEvents: BehaviorKeyEvent[] = [];
        private startTime: number;
        private focusLostCount: number = 0;
        private scrollEvents: number = 0;
        private pageVisibilityChanges: number = 0;
        private maxEvents: number = 500;

        constructor() {
            this.startTime = Date.now();
            this.attachListeners();
        }

        private attachListeners(): void {
            let lastMove = 0;
            document.addEventListener('mousemove', (e) => {
                const now = Date.now();
                if (now - lastMove > 50) {
                    this.addMouseEvent(e.clientX, e.clientY, 'move');
                    lastMove = now;
                }
            });

            document.addEventListener('click', (e) => {
                this.addMouseEvent(e.clientX, e.clientY, 'click');
            });

            document.addEventListener('scroll', () => {
                this.scrollEvents++;
                this.addMouseEvent(window.scrollX, window.scrollY, 'scroll');
            });

            document.addEventListener('keydown', (e) => {
                if (this.keyboardEvents.length < this.maxEvents) {
                    this.keyboardEvents.push({
                        key: e.key.length === 1 ? '*' : e.key,
                        timestamp: Date.now(),
                        type: 'down',
                    });
                }
            });

            document.addEventListener('keyup', (e) => {
                if (this.keyboardEvents.length < this.maxEvents) {
                    this.keyboardEvents.push({
                        key: e.key.length === 1 ? '*' : e.key,
                        timestamp: Date.now(),
                        type: 'up',
                    });
                }
            });

            window.addEventListener('blur', () => {
                this.focusLostCount++;
            });

            document.addEventListener('visibilitychange', () => {
                this.pageVisibilityChanges++;
            });
        }

        private addMouseEvent(x: number, y: number, type: 'move' | 'click' | 'scroll'): void {
            if (this.mouseEvents.length < this.maxEvents) {
                this.mouseEvents.push({ x, y, timestamp: Date.now(), type });
            }
        }

        getData(): BehaviorDataResult {
            return {
                mouseEvents: this.mouseEvents,
                keyboardEvents: this.keyboardEvents,
                totalTime: Date.now() - this.startTime,
                focusLostCount: this.focusLostCount,
                scrollEvents: this.scrollEvents,
                pageVisibilityChanges: this.pageVisibilityChanges,
            };
        }

        reset(): void {
            this.mouseEvents = [];
            this.keyboardEvents = [];
            this.startTime = Date.now();
            this.focusLostCount = 0;
            this.scrollEvents = 0;
            this.pageVisibilityChanges = 0;
        }
    }

    (window as any).behaviorTracker = new EnhancedBehaviorTracker();
})();
