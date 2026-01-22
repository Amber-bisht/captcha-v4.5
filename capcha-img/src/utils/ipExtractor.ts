/**
 * SECURITY FIX P1.4: Centralized IP Extraction Utility
 * 
 * This ensures consistent IP extraction across all middleware and handlers.
 * Uses a standardized priority order and handles edge cases.
 */

import { Request } from 'express';

/**
 * Configuration for trusted proxy headers
 * In production, only trust headers from known reverse proxies
 */
const TRUST_PROXY_HEADERS = process.env.TRUST_PROXY === 'true';

/**
 * Extract the real client IP from a request
 * 
 * Priority order:
 * 1. X-Forwarded-For (first value, if trusted)
 * 2. X-Real-IP (if trusted)
 * 3. Socket remote address
 * 
 * @param req Express request object
 * @returns Client IP address
 */
export function getClientIP(req: Request): string {
    // Only trust proxy headers if configured
    if (TRUST_PROXY_HEADERS) {
        // X-Forwarded-For can contain multiple IPs: "client, proxy1, proxy2"
        const forwardedFor = req.headers['x-forwarded-for'];
        if (forwardedFor) {
            const firstIP = Array.isArray(forwardedFor)
                ? forwardedFor[0]
                : forwardedFor.split(',')[0]?.trim();
            if (firstIP && isValidIP(firstIP)) {
                return firstIP;
            }
        }

        // X-Real-IP is typically set by nginx
        const realIP = req.headers['x-real-ip'];
        if (realIP) {
            const ip = Array.isArray(realIP) ? realIP[0] : realIP;
            if (isValidIP(ip)) {
                return ip;
            }
        }
    }

    // Fall back to socket address
    const socketIP = req.socket?.remoteAddress;
    if (socketIP) {
        // Handle IPv6-mapped IPv4 addresses (::ffff:192.168.1.1)
        if (socketIP.startsWith('::ffff:')) {
            return socketIP.substring(7);
        }
        return socketIP;
    }

    return 'unknown';
}

/**
 * Validate IP address format (basic validation)
 */
function isValidIP(ip: string): boolean {
    if (!ip || typeof ip !== 'string') return false;

    // IPv4 pattern
    const ipv4Pattern = /^(\d{1,3}\.){3}\d{1,3}$/;
    if (ipv4Pattern.test(ip)) {
        const parts = ip.split('.').map(Number);
        return parts.every(n => n >= 0 && n <= 255);
    }

    // IPv6 pattern (simplified check)
    const ipv6Pattern = /^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$/;
    return ipv6Pattern.test(ip);
}

/**
 * Get IP type classification
 */
export function getIPType(ip: string): 'ipv4' | 'ipv6' | 'private' | 'unknown' {
    if (!ip || ip === 'unknown') return 'unknown';

    // Private IPv4 ranges
    const privateRanges = [
        /^10\./,
        /^172\.(1[6-9]|2\d|3[01])\./,
        /^192\.168\./,
        /^127\./,
    ];

    if (privateRanges.some(r => r.test(ip))) {
        return 'private';
    }

    if (ip.includes(':')) return 'ipv6';
    return 'ipv4';
}

export default { getClientIP, getIPType };
