import jwt from 'jsonwebtoken';
import crypto from 'crypto';
import { TokenPayload, TokenResponse, TokenVerificationResult } from '../types/token';
import { setWithTTL, exists, KEYS } from '../config/redis';

// SECURITY FIX P1.1: Require JWT_SECRET to be explicitly set - no fallback
const JWT_SECRET_RAW = process.env.JWT_SECRET;
if (!JWT_SECRET_RAW) {
  console.error('[FATAL] JWT_SECRET environment variable is required but not set');
  process.exit(1);
}
const JWT_SECRET: string = JWT_SECRET_RAW;

const TOKEN_EXPIRATION_MINUTES = 10;

export class TokenService {
  private static secret: string = JWT_SECRET;

  /**
   * Generate a JWT token for a challenge
   */
  static async generateToken(
    challengeId: string,
    fingerprint: string,
    ip: string
  ): Promise<TokenResponse> {
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

    // Store nonce in Redis to prevent replay attacks (TTL matches token expiry)
    await setWithTTL(KEYS.usedNonce(nonce), '1', TOKEN_EXPIRATION_MINUTES * 60);

    return {
      token,
      expiresIn: TOKEN_EXPIRATION_MINUTES * 60,
    };
  }

  /**
   * Verify a JWT token
   */
  static async verifyToken(
    token: string,
    expectedFingerprint: string,
    expectedIp: string
  ): Promise<TokenVerificationResult> {
    try {
      const decoded = jwt.verify(token, this.secret) as TokenPayload;

      // Check if nonce has been used (replay attack prevention via Redis)
      const nonceUsed = await exists(KEYS.usedNonce(decoded.nonce));
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

      // Mark nonce as used in Redis
      await setWithTTL(KEYS.usedNonce(decoded.nonce), 'used', TOKEN_EXPIRATION_MINUTES * 60);

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
    const nonce = crypto.randomBytes(16).toString('hex');
    const timestamp = Date.now();

    const payload = {
      challengeId: 'success',
      nonce,
      timestamp,
      fingerprint,
      ip,
      status: 'verified',
    };

    const token = jwt.sign(payload, this.secret, {
      expiresIn: '90s', // Success tokens expire in 90 seconds
    });

    return {
      token,
      expiresIn: 90,
    };
  }

  /**
   * Verify a success token (for siteverify endpoint)
   * Used for server-to-server validation
   */
  static verifySuccessToken(
    token: string,
    remoteIp?: string
  ): {
    valid: boolean;
    error?: string;
    challengeTs?: string;
    fingerprint?: string;
    ip?: string;
  } {
    try {
      const decoded = jwt.verify(token, this.secret) as {
        challengeId: string;
        nonce: string;
        timestamp: number;
        fingerprint: string;
        ip: string;
        status?: string;
      };

      // Must be a success token
      if (decoded.challengeId !== 'success') {
        return {
          valid: false,
          error: 'invalid-token-type',
        };
      }

      // Check status if present
      if (decoded.status && decoded.status !== 'verified') {
        return {
          valid: false,
          error: 'token-not-verified',
        };
      }

      // Optional IP verification
      if (remoteIp && decoded.ip !== remoteIp) {
        return {
          valid: false,
          error: 'ip-mismatch',
        };
      }

      return {
        valid: true,
        challengeTs: new Date(decoded.timestamp).toISOString(),
        fingerprint: decoded.fingerprint,
        ip: decoded.ip,
      };
    } catch (error) {
      if (error instanceof jwt.TokenExpiredError) {
        return {
          valid: false,
          error: 'token-expired',
        };
      }
      if (error instanceof jwt.JsonWebTokenError) {
        return {
          valid: false,
          error: 'invalid-token',
        };
      }
      return {
        valid: false,
        error: 'verification-failed',
      };
    }
  }
}
