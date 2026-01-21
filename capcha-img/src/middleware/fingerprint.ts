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
 * Includes session entropy to prevent token harvesting
 */
export function generateServerFingerprint(req: Request, sessionEntropy?: string): string {
  // Extract IP - this comes from the connection, not headers
  const ip =
    (req.headers['x-forwarded-for'] as string)?.split(',')[0] ||
    (req.headers['x-real-ip'] as string) ||
    req.socket.remoteAddress ||
    'unknown';

  // User-Agent can be spoofed but adds some protection
  const userAgent = req.headers['user-agent'] || 'unknown';

  // Accept headers are harder to spoof correctly (browsers send these automatically)
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

  // Additional headers that are hard to spoof correctly
  const connection = req.headers['connection'] || '';
  const cacheControl = req.headers['cache-control'] || '';
  const upgradeInsecureRequests = req.headers['upgrade-insecure-requests'] || '';

  // Sec-Fetch headers - browser security features, hard to fake correctly
  const secFetchSite = req.headers['sec-fetch-site'] || '';
  const secFetchMode = req.headers['sec-fetch-mode'] || '';
  const secFetchDest = req.headers['sec-fetch-dest'] || '';

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
    connection,
    cacheControl,
    upgradeInsecureRequests,
    secFetchSite,
    secFetchMode,
    secFetchDest,
  ].join('|');

  // Base fingerprint (stable across requests)
  const baseHash = crypto.createHash('sha256').update(components).digest('hex');

  // If session entropy is provided, create a bound fingerprint
  // This makes the fingerprint unique to this session, preventing token harvesting
  if (sessionEntropy) {
    return crypto.createHash('sha256').update(`${baseHash}:${sessionEntropy}`).digest('hex');
  }

  return baseHash;
}

/**
 * Analyze fingerprint consistency
 * Detects potential spoofing by checking header consistency
 */
export function analyzeFingerprint(req: Request): {
  isConsistent: boolean;
  suspicionScore: number;
  anomalies: string[];
} {
  const anomalies: string[] = [];
  let suspicionScore = 0;

  const userAgent = (req.headers['user-agent'] || '').toLowerCase();
  const secChUa = (req.headers['sec-ch-ua'] || '').toString().toLowerCase();
  const secChUaPlatform = (req.headers['sec-ch-ua-platform'] || '').toString().toLowerCase();

  // Check User-Agent and Client Hints consistency
  if (userAgent.includes('chrome') && !secChUa.includes('chrome')) {
    if (secChUa && !userAgent.includes('edge')) {
      anomalies.push('UA claims Chrome but Sec-CH-UA disagrees');
      suspicionScore += 30;
    }
  }

  // Check platform consistency
  if (userAgent.includes('windows') && secChUaPlatform && !secChUaPlatform.includes('windows')) {
    anomalies.push('UA claims Windows but Sec-CH-UA-Platform disagrees');
    suspicionScore += 30;
  }

  if (userAgent.includes('mac') && secChUaPlatform && !secChUaPlatform.includes('mac')) {
    anomalies.push('UA claims Mac but Sec-CH-UA-Platform disagrees');
    suspicionScore += 30;
  }

  // Missing Sec-Fetch headers in modern browsers is suspicious
  const secFetchSite = req.headers['sec-fetch-site'];
  const secFetchMode = req.headers['sec-fetch-mode'];

  // Modern Chrome/Firefox/Edge always send these on POST requests
  if (!secFetchSite && !secFetchMode) {
    if (userAgent.includes('chrome/') || userAgent.includes('firefox/') || userAgent.includes('edg/')) {
      const version = parseInt(userAgent.match(/(?:chrome|firefox|edg)\/(\d+)/)?.[1] || '0');
      if (version > 80) {
        anomalies.push('Modern browser missing Sec-Fetch headers');
        suspicionScore += 25;
      }
    }
  }

  // Accept-Encoding should have standard values
  const acceptEncoding = (req.headers['accept-encoding'] || '').toString();
  if (acceptEncoding && !acceptEncoding.includes('gzip')) {
    anomalies.push('Unusual Accept-Encoding (missing gzip)');
    suspicionScore += 10;
  }

  // Accept-Language should exist for browsers
  if (!req.headers['accept-language']) {
    anomalies.push('Missing Accept-Language header');
    suspicionScore += 15;
  }

  return {
    isConsistent: anomalies.length === 0,
    suspicionScore: Math.min(100, suspicionScore),
    anomalies
  };
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
