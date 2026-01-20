"use strict";
/**
 * Client-Side Enhanced Behavior Tracker
 * ML-ready behavioral data collection
 * Wrapped in IIFE to avoid global conflicts
 */
(function () {
    class EnhancedBehaviorTracker {
        constructor() {
            this.mouseEvents = [];
            this.keyboardEvents = [];
            this.focusLostCount = 0;
            this.scrollEvents = 0;
            this.pageVisibilityChanges = 0;
            this.maxEvents = 500;
            this.startTime = Date.now();
            this.attachListeners();
        }
        attachListeners() {
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
        addMouseEvent(x, y, type) {
            if (this.mouseEvents.length < this.maxEvents) {
                this.mouseEvents.push({ x, y, timestamp: Date.now(), type });
            }
        }
        getData() {
            return {
                mouseEvents: this.mouseEvents,
                keyboardEvents: this.keyboardEvents,
                totalTime: Date.now() - this.startTime,
                focusLostCount: this.focusLostCount,
                scrollEvents: this.scrollEvents,
                pageVisibilityChanges: this.pageVisibilityChanges,
            };
        }
        reset() {
            this.mouseEvents = [];
            this.keyboardEvents = [];
            this.startTime = Date.now();
            this.focusLostCount = 0;
            this.scrollEvents = 0;
            this.pageVisibilityChanges = 0;
        }
    }
    window.behaviorTracker = new EnhancedBehaviorTracker();
})();
