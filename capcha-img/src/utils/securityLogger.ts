
interface SecurityLogEvent {
    type: string;
    level: 'INFO' | 'WARN' | 'ERROR' | 'CRITICAL';
    message: string;
    ip?: string;
    fingerprint?: string;
    details?: any;
    timestamp?: string;
}

export class SecurityLogger {
    static log(event: SecurityLogEvent) {
        // Ensure timestamp is always present
        const logEntry = {
            timestamp: new Date().toISOString(),
            environment: process.env.NODE_ENV || 'development',
            ...event
        };

        // Output as single-line JSON for easy parsing by monitoring tools (CloudWatch, Datadog, etc.)
        console.log(JSON.stringify(logEntry));
    }

    static info(message: string, context: Partial<SecurityLogEvent> = {}) {
        this.log({ type: 'GENERAL', level: 'INFO', message, ...context });
    }

    static warn(message: string, context: Partial<SecurityLogEvent> = {}) {
        this.log({ type: 'SECURITY_WARNING', level: 'WARN', message, ...context });
    }

    static error(message: string, error?: any, context: Partial<SecurityLogEvent> = {}) {
        this.log({
            type: 'ERROR',
            level: 'ERROR',
            message,
            details: error instanceof Error ? { message: error.message, stack: error.stack } : error,
            ...context
        });
    }

    static critical(message: string, context: Partial<SecurityLogEvent> = {}) {
        this.log({ type: 'SECURITY_CRITICAL', level: 'CRITICAL', message, ...context });
    }
}
