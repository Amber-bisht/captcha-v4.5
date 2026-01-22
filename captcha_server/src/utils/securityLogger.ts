/**
 * Security Logging Service
 * 
 * Centralized logging for security-related events with structured format.
 * Outputs to console (stdout/stderr) which should be captured by logging aggregator (Datadog/CloudWatch etc.)
 */

export type SecurityEventType =
    | 'auth_failure'
    | 'rate_limit_exceeded'
    | 'bot_detected'
    | 'token_reuse'
    | 'ip_reputation'
    | 'challenge_failed'
    | 'challenge_success'
    | 'admin_action'
    | 'system_error';

export interface SecurityEventData {
    ip?: string;
    fingerprint?: string;
    userAgent?: string;
    path?: string;
    method?: string;
    details?: any;
    [key: string]: any;
}

export class SecurityLogger {
    /**
     * Log a security warning (suspicious but handled)
     */
    static warn(message: string, data: SecurityEventData = {}): void {
        this.log('WARN', message, data);
    }

    /**
     * Log a security error (attack blocked or system failure)
     */
    static error(message: string, data: SecurityEventData = {}): void {
        this.log('ERROR', message, data);
    }

    /**
     * Log a security info event (successful access, audit trail)
     */
    static info(message: string, data: SecurityEventData = {}): void {
        this.log('INFO', message, data);
    }

    private static log(level: 'INFO' | 'WARN' | 'ERROR', message: string, data: SecurityEventData): void {
        const timestamp = new Date().toISOString();

        const logEntry = {
            timestamp,
            level,
            type: 'SECURITY_EVENT',
            message,
            ...data
        };

        // Use console methods appropriately
        if (level === 'ERROR') {
            console.error(JSON.stringify(logEntry));
        } else if (level === 'WARN') {
            console.warn(JSON.stringify(logEntry));
        } else {
            console.log(JSON.stringify(logEntry));
        }
    }
}

export default SecurityLogger;
