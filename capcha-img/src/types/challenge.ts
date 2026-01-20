export interface ImageChallenge {
  sessionId: string;
  targetCategory: string;
  images: string[];
  validAnswers: string[];
  question: string;
  createdAt: number;
  expiresAt: number;
}

export interface ChallengeConfig {
  gridSize: number;
  minCorrectAnswers: number;
  maxCorrectAnswers: number;
  rotationRange: {
    min: number;
    max: number;
  };
  expirationMinutes: number;
}
