import crypto from 'crypto';
import { ImageChallenge, ChallengeConfig } from '../types/challenge';

const DEFAULT_CONFIG: ChallengeConfig = {
  gridSize: 9,
  minCorrectAnswers: 2,
  maxCorrectAnswers: 4,
  rotationRange: {
    min: 1,
    max: 5,
  },
  expirationMinutes: 5,
};

export class ChallengeGenerator {
  /**
   * Generate an image selection challenge
   */
  static generateChallenge(
    files: string[],
    config: ChallengeConfig = DEFAULT_CONFIG
  ): ImageChallenge | null {
    if (files.length === 0) {
      return null;
    }

    // Extract categories from filenames
    const categories = new Set<string>();
    const fileToCategory = new Map<string, string>();

    files.forEach((file) => {
      const parts = file.split('_');
      if (parts.length > 1) {
        const category = parts[0].toLowerCase();
        categories.add(category);
        fileToCategory.set(file, category);
      }
    });

    if (categories.size === 0) {
      return null;
    }

    // Pick a random target category
    const categoryArray = Array.from(categories);
    const targetCategory =
      categoryArray[Math.floor(Math.random() * categoryArray.length)];

    // Select images
    const correctImages = files.filter(
      (f) => fileToCategory.get(f) === targetCategory
    );
    const otherImages = files.filter(
      (f) => fileToCategory.get(f) !== targetCategory
    );

    // Determine number of correct answers (random between min and max)
    const numCorrect = Math.min(
      Math.floor(
        Math.random() * (config.maxCorrectAnswers - config.minCorrectAnswers + 1)
      ) + config.minCorrectAnswers,
      correctImages.length
    );

    // Select correct images
    const selectedCorrect = this.shuffleArray(correctImages).slice(0, numCorrect);

    // Fill remaining slots with distractors
    const remainingSlots = config.gridSize - selectedCorrect.length;
    const selectedDistractors = this.shuffleArray(otherImages).slice(
      0,
      Math.min(remainingSlots, otherImages.length)
    );

    // Combine and shuffle
    const allImages = this.shuffleArray([
      ...selectedCorrect,
      ...selectedDistractors,
    ]);

    const sessionId =
      Date.now().toString() + crypto.randomBytes(8).toString('hex');
    const createdAt = Date.now();
    const expiresAt =
      createdAt + config.expirationMinutes * 60 * 1000;

    return {
      sessionId,
      targetCategory,
      images: allImages,
      validAnswers: selectedCorrect,
      question: `Select all images containing a ${targetCategory}`,
      createdAt,
      expiresAt,
    };
  }

  /**
   * Shuffle array using Fisher-Yates algorithm
   */
  private static shuffleArray<T>(array: T[]): T[] {
    const shuffled = [...array];
    for (let i = shuffled.length - 1; i > 0; i--) {
      const j = Math.floor(Math.random() * (i + 1));
      [shuffled[i], shuffled[j]] = [shuffled[j], shuffled[i]];
    }
    return shuffled;
  }

  /**
   * Check if challenge is expired
   */
  static isExpired(challenge: ImageChallenge): boolean {
    return Date.now() > challenge.expiresAt;
  }

  /**
   * Apply random rotation to image (for client-side rendering)
   */
  static getImageRotation(): number {
    const config = DEFAULT_CONFIG;
    const rotation =
      Math.random() * (config.rotationRange.max - config.rotationRange.min) +
      config.rotationRange.min;
    return Math.random() > 0.5 ? rotation : -rotation;
  }
}
