import jwt from 'jsonwebtoken';
import crypto from 'crypto';
import { TokenPayload, TokenResponse, TokenVerificationResult } from '../types/token';

const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(32).toString('hex');
const TOKEN_EXPIRATION_MINUTES = 10;

export class TokenService {
  private static secret: string = JWT_SECRET;
  private static usedNonces: Set<string> = new Set();

  /**
   * Generate a JWT token for a challenge
   */
  static generateToken(
    challengeId: string,
    fingerprint: string,
    ip: string
  ): TokenResponse {
    const nonce = crypto.randomBytes(16).toString('hex');
    const timestamp = Date.now();

    const payload: TokenPayload = {
      challengeId,
      nonce,
      timestamp,
      fingerprint,
      ip,
    };

    const token = jwt.sign(payload, this.secret, {
      expiresIn: `${TOKEN_EXPIRATION_MINUTES}m`,
    });

    return {
      token,
      expiresIn: TOKEN_EXPIRATION_MINUTES * 60,
    };
  }

  /**
   * Verify a JWT token
   */
  static verifyToken(
    token: string,
    expectedFingerprint: string,
    expectedIp: string
  ): TokenVerificationResult {
    try {
      const decoded = jwt.verify(token, this.secret) as TokenPayload;

      // Check if nonce has been used (replay attack prevention)
      if (this.usedNonces.has(decoded.nonce)) {
        return {
          valid: false,
          error: 'Token has already been used',
        };
      }

      // Check fingerprint match
      if (decoded.fingerprint !== expectedFingerprint) {
        return {
          valid: false,
          error: 'Fingerprint mismatch',
        };
      }

      // Check IP match
      if (decoded.ip !== expectedIp) {
        return {
          valid: false,
          error: 'IP address mismatch',
        };
      }

      // Mark nonce as used and schedule cleanup
      this.usedNonces.add(decoded.nonce);
      setTimeout(() => {
        this.usedNonces.delete(decoded.nonce);
      }, TOKEN_EXPIRATION_MINUTES * 60 * 1000);

      return {
        valid: true,
        payload: decoded,
      };
    } catch (error) {
      if (error instanceof jwt.TokenExpiredError) {
        return {
          valid: false,
          error: 'Token expired',
        };
      }
      if (error instanceof jwt.JsonWebTokenError) {
        return {
          valid: false,
          error: 'Invalid token',
        };
      }
      return {
        valid: false,
        error: 'Token verification failed',
      };
    }
  }

  /**
   * Generate a success token after verification
   */
  static generateSuccessToken(fingerprint: string, ip: string): TokenResponse {
    const challengeId = 'success';
    return this.generateToken(challengeId, fingerprint, ip);
  }
}
