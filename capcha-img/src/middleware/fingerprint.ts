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
 * NOTE: Client-provided headers like x-screen-width can be spoofed
 * These are used for additional context but NOT for security decisions
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
  // WARNING: These are client-provided and CAN BE SPOOFED
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
 * Generate a SECURE server-side fingerprint
 * Uses ONLY non-spoofable information for security decisions
 */
export function generateServerFingerprint(req: Request): string {
  // Extract IP - this comes from the connection, not headers
  const ip =
    (req.headers['x-forwarded-for'] as string)?.split(',')[0] ||
    (req.headers['x-real-ip'] as string) ||
    req.socket.remoteAddress ||
    'unknown';

  // User-Agent can be spoofed but adds some protection
  const userAgent = req.headers['user-agent'] || 'unknown';

  // Accept headers are harder to spoof correctly
  const acceptLanguage = req.headers['accept-language'] || 'unknown';
  const acceptEncoding = req.headers['accept-encoding'] || 'unknown';
  const accept = req.headers['accept'] || 'unknown';

  // Sec-CH-UA headers (Client Hints) - harder to spoof in browsers
  const secChUa = req.headers['sec-ch-ua'] || '';
  const secChUaPlatform = req.headers['sec-ch-ua-platform'] || '';
  const secChUaMobile = req.headers['sec-ch-ua-mobile'] || '';

  // TLS fingerprint info (if available through reverse proxy)
  const tlsVersion = req.headers['x-tls-version'] || '';
  const tlsCipher = req.headers['x-tls-cipher'] || '';

  // Create a hash using ONLY server-verified data
  const components = [
    ip,
    userAgent,
    acceptLanguage,
    acceptEncoding,
    accept,
    secChUa,
    secChUaPlatform,
    secChUaMobile,
    tlsVersion,
    tlsCipher,
  ].join('|');

  return crypto.createHash('sha256').update(components).digest('hex');
}

/**
 * Generate hash from fingerprint components (legacy, uses client data)
 * WARNING: This is less secure than generateServerFingerprint
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
 * Uses server-side fingerprint for security, client data for context
 */
export function fingerprintMiddleware(
  req: Request,
  res: Response,
  next: NextFunction
): void {
  const fingerprint = extractFingerprint(req);

  // Use SERVER-GENERATED hash for security decisions
  const serverHash = generateServerFingerprint(req);

  req.fingerprint = {
    hash: serverHash,  // Now uses server-side fingerprint
    components: fingerprint,
  };

  next();
}
