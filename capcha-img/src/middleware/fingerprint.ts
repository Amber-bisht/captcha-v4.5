import { Request, Response, NextFunction } from 'express';
import crypto from 'crypto';
import { BrowserFingerprint, FingerprintHash } from '../types/fingerprint';

declare global {
  namespace Express {
    interface Request {
      fingerprint?: FingerprintHash;
    }
  }
}

/**
 * Extract browser fingerprint from request
 */
export function extractFingerprint(req: Request): BrowserFingerprint {
  const ip =
    (req.headers['x-forwarded-for'] as string)?.split(',')[0] ||
    (req.headers['x-real-ip'] as string) ||
    req.socket.remoteAddress ||
    'unknown';

  const userAgent = req.headers['user-agent'] || 'unknown';
  const acceptLanguage = req.headers['accept-language'] || 'unknown';

  // Extract screen size from headers if available (set by client-side script)
  const screenWidth = parseInt(req.headers['x-screen-width'] as string) || 0;
  const screenHeight = parseInt(req.headers['x-screen-height'] as string) || 0;
  const timezone = (req.headers['x-timezone'] as string) || 'unknown';

  return {
    ip,
    userAgent,
    acceptLanguage,
    screenSize: {
      width: screenWidth,
      height: screenHeight,
    },
    timezone,
    canvas: req.headers['x-canvas-fingerprint'] as string | undefined,
    webgl: req.headers['x-webgl-fingerprint'] as string | undefined,
    audio: req.headers['x-audio-fingerprint'] as string | undefined,
  };
}

/**
 * Generate hash from fingerprint components
 */
export function hashFingerprint(fingerprint: BrowserFingerprint): string {
  const components = [
    fingerprint.ip,
    fingerprint.userAgent,
    fingerprint.acceptLanguage,
    fingerprint.timezone,
    fingerprint.canvas || '',
    fingerprint.webgl || '',
    fingerprint.audio || '',
    `${fingerprint.screenSize.width}x${fingerprint.screenSize.height}`,
  ].join('|');

  return crypto.createHash('sha256').update(components).digest('hex');
}

/**
 * Middleware to attach fingerprint to request
 */
export function fingerprintMiddleware(
  req: Request,
  res: Response,
  next: NextFunction
): void {
  const fingerprint = extractFingerprint(req);
  const hash = hashFingerprint(fingerprint);

  req.fingerprint = {
    hash,
    components: fingerprint,
  };

  next();
}
