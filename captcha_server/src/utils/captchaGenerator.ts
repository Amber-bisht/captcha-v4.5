import svgCaptcha from 'svg-captcha';
import crypto from 'crypto';
import { CaptchaConfig, CaptchaChallenge } from '../types/captcha';

const CHALLENGE_EXPIRATION_MINUTES = 5;

export class CaptchaGenerator {
  /**
   * Generate an enhanced CAPTCHA challenge
   */
  static generateChallenge(): CaptchaChallenge {
    const challengeId = crypto.randomBytes(16).toString('hex');
    const createdAt = Date.now();
    const expiresAt = createdAt + CHALLENGE_EXPIRATION_MINUTES * 60 * 1000;

    // Enhanced configuration with anti-OCR techniques
    const config: CaptchaConfig = {
      size: 5,
      ignoreChars: '0o1il',
      noise: Math.floor(Math.random() * 3) + 2, // Random noise between 2-4
      color: true,
      background: this.getRandomBackgroundColor(),
      fontSize: Math.floor(Math.random() * 20) + 40, // Random font size 40-60
      width: 150,
      height: 50,
    };

    const captcha = svgCaptcha.create(config);

    return {
      id: challengeId,
      image: captcha.data,
      text: captcha.text,
      createdAt,
      expiresAt,
    };
  }

  /**
   * Get random background color
   */
  private static getRandomBackgroundColor(): string {
    const colors = [
      '#cc9966',
      '#9966cc',
      '#66cc99',
      '#cc6699',
      '#99cc66',
      '#6699cc',
    ];
    return colors[Math.floor(Math.random() * colors.length)];
  }

  /**
   * Check if challenge is expired
   */
  static isExpired(challenge: CaptchaChallenge): boolean {
    return Date.now() > challenge.expiresAt;
  }
}
