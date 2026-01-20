import { Request, Response, NextFunction } from 'express';
import crypto from 'crypto';
import { CSRFToken, CSRFVerificationResult } from '../types/csrf';

const CSRF_TOKEN_EXPIRATION = 30 * 60 * 1000; // 30 minutes
const CSRF_TOKEN_COOKIE_NAME = 'csrf-token';

declare global {
  namespace Express {
    interface Request {
      csrfToken?: string;
    }
  }
}

/**
 * Generate a CSRF token
 */
export function generateCSRFToken(): CSRFToken {
  const token = crypto.randomBytes(32).toString('hex');
  return {
    token,
    expiresAt: Date.now() + CSRF_TOKEN_EXPIRATION,
  };
}

/**
 * Middleware to generate and set CSRF token
 */
export function csrfTokenMiddleware(
  req: Request,
  res: Response,
  next: NextFunction
): void {
  // Generate new token if not exists or expired
  const existingToken = req.cookies?.[CSRF_TOKEN_COOKIE_NAME];
  let csrfToken: CSRFToken;

  if (existingToken) {
    try {
      const parsed = JSON.parse(Buffer.from(existingToken, 'base64').toString());
      if (parsed.expiresAt > Date.now()) {
        csrfToken = parsed;
        req.csrfToken = csrfToken.token;
        return next();
      }
    } catch {
      // Invalid token, generate new one
    }
  }

  csrfToken = generateCSRFToken();
  req.csrfToken = csrfToken.token;

  // Set cookie
  res.cookie(CSRF_TOKEN_COOKIE_NAME, Buffer.from(JSON.stringify(csrfToken)).toString('base64'), {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict',
    maxAge: CSRF_TOKEN_EXPIRATION,
  });

  next();
}

/**
 * Verify CSRF token
 */
export function verifyCSRFToken(req: Request): CSRFVerificationResult {
  const cookieToken = req.cookies?.[CSRF_TOKEN_COOKIE_NAME];
  const headerToken = req.headers['x-csrf-token'] as string;

  if (!cookieToken || !headerToken) {
    return {
      valid: false,
      error: 'CSRF token missing',
    };
  }

  try {
    const parsed = JSON.parse(Buffer.from(cookieToken, 'base64').toString());
    if (parsed.expiresAt < Date.now()) {
      return {
        valid: false,
        error: 'CSRF token expired',
      };
    }

    if (parsed.token !== headerToken) {
      return {
        valid: false,
        error: 'CSRF token mismatch',
      };
    }

    return {
      valid: true,
    };
  } catch {
    return {
      valid: false,
      error: 'Invalid CSRF token format',
    };
  }
}

/**
 * CSRF verification middleware
 */
export function csrfVerificationMiddleware(
  req: Request,
  res: Response,
  next: NextFunction
): void {
  const result = verifyCSRFToken(req);
  if (!result.valid) {
    res.status(403).json({
      success: false,
      message: result.error || 'CSRF verification failed',
    });
    return;
  }
  next();
}
