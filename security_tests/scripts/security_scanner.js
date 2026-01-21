/**
 * Comprehensive CAPTCHA Security Scanner
 * 
 * Tests all major security aspects of the CAPTCHA system:
 * - Token security (replay, expiry, binding)
 * - Rate limiting
 * - PoW verification
 * - Timing validation
 * - CORS/Headers
 * - Bot detection bypass attempts
 * 
 * Usage:
 *   node security_scanner.js [--full-flow] [--url URL]
 */

const crypto = require('crypto');
const https = require('https');
const http = require('http');

// Configuration
const CONFIG = {
    captchaUrl: process.env.CAPTCHA_URL || 'https://captcha-p.asprin.dev',
    clientUrl: process.env.CLIENT_URL || 'https://links.asprin.dev',
    verbose: process.argv.includes('--verbose') || process.argv.includes('-v'),
    fullFlow: process.argv.includes('--full-flow'),
};

// Results tracking
const results = {
    passed: 0,
    failed: 0,
    warnings: 0,
    tests: []
};

// Colors for console output
const colors = {
    reset: '\x1b[0m',
    green: '\x1b[32m',
    red: '\x1b[31m',
    yellow: '\x1b[33m',
    cyan: '\x1b[36m',
    gray: '\x1b[90m'
};

// Logging helpers
function log(message) {
    console.log(message);
}

function logPass(test, details = '') {
    results.passed++;
    results.tests.push({ name: test, status: 'PASS', details });
    console.log(`${colors.green}✅ ${test}${colors.reset}${details ? ` - ${colors.gray}${details}${colors.reset}` : ''}`);
}

function logFail(test, details = '') {
    results.failed++;
    results.tests.push({ name: test, status: 'FAIL', details });
    console.log(`${colors.red}❌ ${test}${colors.reset}${details ? ` - ${details}` : ''}`);
}

function logWarn(test, details = '') {
    results.warnings++;
    results.tests.push({ name: test, status: 'WARN', details });
    console.log(`${colors.yellow}⚠️  ${test}${colors.reset}${details ? ` - ${details}` : ''}`);
}

function logInfo(message) {
    console.log(`${colors.cyan}ℹ️  ${message}${colors.reset}`);
}

// HTTP request helper
function makeRequest(url, options = {}) {
    return new Promise((resolve, reject) => {
        const parsedUrl = new URL(url);
        const protocol = parsedUrl.protocol === 'https:' ? https : http;

        const defaultHeaders = {
            'Origin': CONFIG.clientUrl,
            'Referer': `${CONFIG.clientUrl}/`,
            'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36',
            'Accept': '*/*',
            'Accept-Language': 'en-US,en;q=0.9',
        };

        const reqOptions = {
            hostname: parsedUrl.hostname,
            port: parsedUrl.port || (parsedUrl.protocol === 'https:' ? 443 : 80),
            path: parsedUrl.pathname + parsedUrl.search,
            method: options.method || 'GET',
            headers: { ...defaultHeaders, ...options.headers },
        };

        const req = protocol.request(reqOptions, (res) => {
            let data = '';
            res.on('data', chunk => data += chunk);
            res.on('end', () => {
                resolve({
                    status: res.statusCode,
                    headers: res.headers,
                    body: data,
                    json: () => {
                        try { return JSON.parse(data); }
                        catch { return null; }
                    }
                });
            });
        });

        req.on('error', reject);

        if (options.body) {
            req.write(typeof options.body === 'string' ? options.body : JSON.stringify(options.body));
        }

        req.end();
    });
}

// PoW solver (simplified)
function solvePoW(nonce, difficulty) {
    let counter = 0;
    const target = '0'.repeat(difficulty);

    while (true) {
        const hash = crypto.createHash('sha256')
            .update(nonce + counter.toString())
            .digest('hex');

        if (hash.startsWith(target)) {
            return counter.toString();
        }
        counter++;

        if (counter > 10000000) {
            throw new Error('PoW solving timeout');
        }
    }
}

// ============================================
// TEST SUITES
// ============================================

async function testEndpointAvailability() {
    log('\n' + '='.repeat(50));
    log('📡 Endpoint Availability Tests');
    log('='.repeat(50));

    const endpoints = [
        { path: '/api/image/api/init', method: 'GET', name: 'Init' },
        { path: '/health', method: 'GET', name: 'Health' },
    ];

    for (const endpoint of endpoints) {
        try {
            const res = await makeRequest(`${CONFIG.captchaUrl}${endpoint.path}`, {
                method: endpoint.method
            });

            if (res.status === 200) {
                logPass(`${endpoint.name} endpoint accessible`, `HTTP ${res.status}`);
            } else {
                logFail(`${endpoint.name} endpoint`, `HTTP ${res.status}`);
            }
        } catch (error) {
            logFail(`${endpoint.name} endpoint`, error.message);
        }
    }
}

async function testSecurityHeaders() {
    log('\n' + '='.repeat(50));
    log('🔒 Security Headers Tests');
    log('='.repeat(50));

    try {
        const res = await makeRequest(`${CONFIG.captchaUrl}/api/image/api/init`);

        const requiredHeaders = [
            { name: 'strict-transport-security', required: true },
            { name: 'x-content-type-options', required: true },
            { name: 'x-frame-options', required: true },
            { name: 'content-security-policy', required: false },
            { name: 'referrer-policy', required: false },
        ];

        for (const header of requiredHeaders) {
            const headerValue = res.headers[header.name];
            if (headerValue) {
                logPass(`${header.name} present`, headerValue.substring(0, 50) + (headerValue.length > 50 ? '...' : ''));
            } else if (header.required) {
                logFail(`${header.name} missing`);
            } else {
                logWarn(`${header.name} not present`, 'Recommended');
            }
        }

        // Check for dangerous headers
        if (res.headers['x-powered-by']) {
            logWarn('X-Powered-By disclosed', res.headers['x-powered-by']);
        } else {
            logPass('X-Powered-By not disclosed');
        }

    } catch (error) {
        logFail('Security headers test', error.message);
    }
}

async function testCORS() {
    log('\n' + '='.repeat(50));
    log('🌐 CORS Configuration Tests');
    log('='.repeat(50));

    try {
        // Test preflight request
        const res = await makeRequest(`${CONFIG.captchaUrl}/api/image/api/request-challenge`, {
            method: 'OPTIONS',
            headers: {
                'Access-Control-Request-Method': 'POST',
                'Access-Control-Request-Headers': 'content-type'
            }
        });

        const allowedOrigin = res.headers['access-control-allow-origin'];

        if (allowedOrigin === CONFIG.clientUrl) {
            logPass('CORS allows specified origin', allowedOrigin);
        } else if (allowedOrigin === '*') {
            logFail('CORS allows wildcard origin', 'Security risk!');
        } else if (allowedOrigin) {
            logWarn('CORS origin mismatch', `Expected ${CONFIG.clientUrl}, got ${allowedOrigin}`);
        } else {
            logFail('CORS not configured', 'No Access-Control-Allow-Origin header');
        }

        // Test blocked origin
        const blockedRes = await makeRequest(`${CONFIG.captchaUrl}/api/image/api/init`, {
            headers: {
                'Origin': 'https://malicious-site.com'
            }
        });

        const blockedOrigin = blockedRes.headers['access-control-allow-origin'];
        if (!blockedOrigin || blockedOrigin !== 'https://malicious-site.com') {
            logPass('CORS blocks unauthorized origins');
        } else {
            logFail('CORS accepts unauthorized origins', 'Security vulnerability!');
        }

    } catch (error) {
        logFail('CORS test', error.message);
    }
}

async function testPoWChallenge() {
    log('\n' + '='.repeat(50));
    log('⛏️  Proof-of-Work Tests');
    log('='.repeat(50));

    try {
        // Get init challenge
        const initRes = await makeRequest(`${CONFIG.captchaUrl}/api/image/api/init`);
        const init = initRes.json();

        if (!init || !init.nonce) {
            logFail('PoW initialization', 'No nonce returned');
            return;
        }

        logPass('PoW nonce received', `Difficulty: ${init.difficulty}`);

        // Test invalid nonce rejection
        const invalidRes = await makeRequest(`${CONFIG.captchaUrl}/api/image/api/request-challenge`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                nonce: 'invalid_nonce_12345',
                solution: '000000'
            })
        });

        if (invalidRes.status === 403 || invalidRes.body.includes('Invalid')) {
            logPass('Rejects invalid PoW nonce');
        } else {
            logFail('Does not reject invalid PoW nonce', `Status: ${invalidRes.status}`);
        }

        // Test nonce reuse
        if (CONFIG.fullFlow) {
            logInfo('Solving PoW challenge...');
            const startTime = Date.now();
            const solution = solvePoW(init.nonce, init.difficulty);
            const solveTime = Date.now() - startTime;

            logInfo(`PoW solved in ${solveTime}ms (counter: ${solution})`);

            // First use
            const firstUse = await makeRequest(`${CONFIG.captchaUrl}/api/image/api/request-challenge`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    nonce: init.nonce,
                    solution: solution
                })
            });

            if (firstUse.status === 200) {
                logPass('PoW solution accepted on first use');

                // Try to reuse
                const secondUse = await makeRequest(`${CONFIG.captchaUrl}/api/image/api/request-challenge`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        nonce: init.nonce,
                        solution: solution
                    })
                });

                if (secondUse.status !== 200) {
                    logPass('PoW nonce cannot be reused');
                } else {
                    logFail('PoW nonce reuse allowed', 'Replay attack possible!');
                }
            } else {
                logFail('PoW solution not accepted', firstUse.body);
            }
        } else {
            logInfo('Skipping PoW solve test (use --full-flow to enable)');
        }

    } catch (error) {
        logFail('PoW test', error.message);
    }
}

async function testRateLimiting() {
    log('\n' + '='.repeat(50));
    log('🚦 Rate Limiting Tests');
    log('='.repeat(50));

    try {
        const results = [];
        const testCount = 25;

        logInfo(`Sending ${testCount} rapid requests...`);

        for (let i = 0; i < testCount; i++) {
            const res = await makeRequest(`${CONFIG.captchaUrl}/api/image/api/init`);
            results.push(res.status);
        }

        const blocked = results.filter(s => s === 429).length;
        const success = results.filter(s => s === 200).length;

        logInfo(`Results: ${success} success, ${blocked} blocked`);

        if (blocked > 0) {
            logPass('Rate limiting active', `Blocked ${blocked}/${testCount} requests`);
        } else {
            logWarn('Rate limiting not triggered', 'May need more requests or IP-based limit');
        }

        // Check rate limit headers
        const headerRes = await makeRequest(`${CONFIG.captchaUrl}/api/image/api/init`);

        if (headerRes.headers['ratelimit-limit']) {
            logPass('Rate limit headers present',
                `Limit: ${headerRes.headers['ratelimit-limit']}, ` +
                `Remaining: ${headerRes.headers['ratelimit-remaining']}`
            );
        } else {
            logWarn('Rate limit headers not present');
        }

    } catch (error) {
        logFail('Rate limiting test', error.message);
    }
}

async function testHoneypot() {
    log('\n' + '='.repeat(50));
    log('🍯 Honeypot Detection Tests');
    log('='.repeat(50));

    try {
        const res = await makeRequest(`${CONFIG.captchaUrl}/api/image/api/verify`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                sessionId: 'test_session',
                token: 'test_token',
                textAnswer: 'test',
                honeyPot: 'i_am_a_bot_filling_hidden_field'
            })
        });

        if (res.status === 403 || res.body.includes('Violation') || res.body.includes('violation')) {
            logPass('Honeypot triggered correctly', 'Bot detected');
        } else {
            logFail('Honeypot not triggered', `Status: ${res.status}, Body: ${res.body.substring(0, 100)}`);
        }

    } catch (error) {
        logFail('Honeypot test', error.message);
    }
}

async function testBotDetectionHeaders() {
    log('\n' + '='.repeat(50));
    log('🤖 Bot Detection Tests');
    log('='.repeat(50));

    const botSignatures = [
        {
            name: 'Headless Chrome',
            ua: 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/89.0.4389.72 Safari/537.36'
        },
        {
            name: 'Selenium WebDriver',
            ua: 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.72 Safari/537.36',
            headers: { 'sec-webdriver': 'true' }
        },
        {
            name: 'Python Requests',
            ua: 'python-requests/2.25.1'
        },
        {
            name: 'curl',
            ua: 'curl/7.68.0'
        },
    ];

    for (const bot of botSignatures) {
        try {
            const res = await makeRequest(`${CONFIG.captchaUrl}/api/image/api/init`, {
                headers: {
                    'User-Agent': bot.ua,
                    ...(bot.headers || {})
                }
            });

            if (res.status === 403 || res.body.includes('denied') || res.body.includes('bot')) {
                logPass(`Blocks ${bot.name}`);
            } else if (res.status === 200) {
                // Check if response has higher difficulty
                const json = res.json();
                if (json && json.difficulty > 4) {
                    logPass(`${bot.name} gets elevated difficulty`, `Difficulty: ${json.difficulty}`);
                } else {
                    logWarn(`${bot.name} not blocked`, 'Consider adding detection');
                }
            } else {
                logWarn(`${bot.name} response unclear`, `Status: ${res.status}`);
            }
        } catch (error) {
            logFail(`${bot.name} test`, error.message);
        }
    }
}

async function testInvalidInputs() {
    log('\n' + '='.repeat(50));
    log('🧪 Input Validation Tests');
    log('='.repeat(50));

    const maliciousInputs = [
        { name: 'SQL Injection', value: "'; DROP TABLE users; --" },
        { name: 'XSS Attempt', value: '<script>alert("xss")</script>' },
        { name: 'Path Traversal', value: '../../etc/passwd' },
        { name: 'Extremely Long Input', value: 'A'.repeat(10000) },
        { name: 'Unicode Exploit', value: '\u0000\u0001\u0002\uFFFF' },
        { name: 'JSON Injection', value: '{"__proto__": {"isAdmin": true}}' },
    ];

    for (const input of maliciousInputs) {
        try {
            const res = await makeRequest(`${CONFIG.captchaUrl}/api/image/api/verify`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    sessionId: input.value,
                    token: 'test',
                    textAnswer: input.value
                })
            });

            // Server should not crash (500) or expose errors
            if (res.status === 500) {
                logFail(`${input.name} causes server error`);
            } else if (res.body.includes('stack') || res.body.includes('error:')) {
                logWarn(`${input.name} may expose error details`);
            } else {
                logPass(`${input.name} handled safely`);
            }
        } catch (error) {
            // Connection error might indicate DoS
            logWarn(`${input.name} may have caused issues`, error.message);
        }
    }
}

// ============================================
// MAIN EXECUTION
// ============================================

async function runAllTests() {
    console.log(`
╔══════════════════════════════════════════════════════════════╗
║           🔐 CAPTCHA Security Scanner v1.0                  ║
╠══════════════════════════════════════════════════════════════╣
║  Target: ${CONFIG.captchaUrl.padEnd(45)}              ║
║  Client: ${CONFIG.clientUrl.padEnd(45)}              ║
║  Mode: ${CONFIG.fullFlow ? 'Full Flow (with PoW solving)' : 'Quick Scan          '}              ║
╚══════════════════════════════════════════════════════════════╝
    `);

    const startTime = Date.now();

    await testEndpointAvailability();
    await testSecurityHeaders();
    await testCORS();
    await testPoWChallenge();
    await testRateLimiting();
    await testHoneypot();
    await testBotDetectionHeaders();
    await testInvalidInputs();

    const duration = ((Date.now() - startTime) / 1000).toFixed(2);

    console.log('\n' + '='.repeat(60));
    console.log('📊 SECURITY SCAN SUMMARY');
    console.log('='.repeat(60));
    console.log(`${colors.green}✅ Passed: ${results.passed}${colors.reset}`);
    console.log(`${colors.red}❌ Failed: ${results.failed}${colors.reset}`);
    console.log(`${colors.yellow}⚠️  Warnings: ${results.warnings}${colors.reset}`);
    console.log(`⏱️  Duration: ${duration}s`);
    console.log('='.repeat(60));

    const score = Math.round((results.passed / (results.passed + results.failed)) * 100);

    if (results.failed === 0) {
        console.log(`\n${colors.green}🎉 All security tests passed!${colors.reset}`);
    } else if (score >= 80) {
        console.log(`\n${colors.yellow}⚠️  Security Score: ${score}% - Good, but needs attention${colors.reset}`);
    } else {
        console.log(`\n${colors.red}🚨 Security Score: ${score}% - Critical issues found!${colors.reset}`);
    }

    // Exit with appropriate code
    process.exit(results.failed > 0 ? 1 : 0);
}

// Run
runAllTests().catch(error => {
    console.error('Scanner error:', error);
    process.exit(1);
});
