import jwt from 'jsonwebtoken';
import crypto from 'crypto';
import { TokenPayload, TokenResponse, TokenVerificationResult } from '../types/token';
import RedisStore from './redisStore';

// SECURITY FIX: Require JWT_SECRET to be explicitly set
const JWT_SECRET_RAW = process.env.JWT_SECRET;
if (!JWT_SECRET_RAW) {
  console.error('[FATAL] JWT_SECRET environment variable is required but not set');
  process.exit(1);
}
const JWT_SECRET: string = JWT_SECRET_RAW;
// SECURITY: Reduced from 10 minutes to 90 seconds to minimize replay attack window
const TOKEN_EXPIRATION_SECONDS = 90;

export class TokenService {
  private static secret: string = JWT_SECRET;

  /**
   * Generate a JWT token for a challenge
   */
  static generateToken(
    challengeId: string,
    fingerprint: string,
    ip: string,
    status: 'pending' | 'verified' = 'pending'
  ): TokenResponse {
    const nonce = crypto.randomBytes(16).toString('hex');
    const timestamp = Date.now();

    const payload: TokenPayload = {
      challengeId,
      nonce,
      timestamp,
      fingerprint,
      ip,
      status
    };

    const token = jwt.sign(payload, this.secret, {
      expiresIn: `${TOKEN_EXPIRATION_SECONDS}s`,
    });

    return {
      token,
      expiresIn: TOKEN_EXPIRATION_SECONDS,
    };
  }

  /**
   * Verify a JWT token
   * UPDATED: Uses Redis for nonce tracking instead of in-memory Set
   */
  static async verifyToken(
    token: string,
    expectedFingerprint: string,
    expectedIp: string
  ): Promise<TokenVerificationResult> {
    try {
      const decoded = jwt.verify(token, this.secret) as TokenPayload;

      // Check if nonce has been used (replay attack prevention) - NOW USES REDIS
      const nonceUsed = await RedisStore.isNonceUsed(decoded.nonce);
      if (nonceUsed) {
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

      // Mark nonce as used in Redis (with automatic TTL expiration)
      await RedisStore.markNonceUsed(decoded.nonce);

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
    return this.generateToken(challengeId, fingerprint, ip, 'verified');
  }
}
