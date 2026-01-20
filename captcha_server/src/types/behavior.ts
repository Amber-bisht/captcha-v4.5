export type BehaviorEventType = 'mousemove' | 'click' | 'keypress' | 'scroll' | 'focus';

export interface BehaviorEvent {
  type: BehaviorEventType;
  timestamp: number;
  coordinates?: {
    x: number;
    y: number;
  };
  timing?: number;
  target?: string;
}

export interface BehaviorData {
  events: BehaviorEvent[];
  totalTime: number;
  mouseMovements: number;
  clicks: number;
  averageSpeed?: number;
}

export interface BehaviorScore {
  score: number;
  riskLevel: 'low' | 'medium' | 'high';
  reasons: string[];
}
