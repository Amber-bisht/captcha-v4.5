"use strict";
/**
 * Client-side browser fingerprinting
 */
/**
 * Generate canvas fingerprint
 */
function getCanvasFingerprint() {
    try {
        const canvas = document.createElement('canvas');
        const ctx = canvas.getContext('2d');
        if (!ctx)
            return '';
        ctx.textBaseline = 'top';
        ctx.font = '14px Arial';
        ctx.textBaseline = 'alphabetic';
        ctx.fillStyle = '#f60';
        ctx.fillRect(125, 1, 62, 20);
        ctx.fillStyle = '#069';
        ctx.fillText('Fingerprint', 2, 15);
        ctx.fillStyle = 'rgba(102, 204, 0, 0.7)';
        ctx.fillText('Fingerprint', 4, 17);
        return canvas.toDataURL();
    }
    catch {
        return '';
    }
}
function getWebGLFingerprint() {
    try {
        const canvas = document.createElement('canvas');
        const gl = canvas.getContext('webgl');
        if (!gl)
            return '';
        const debugInfo = gl.getExtension('WEBGL_debug_renderer_info');
        if (!debugInfo)
            return '';
        return (gl.getParameter(debugInfo.UNMASKED_VENDOR_WEBGL) +
            '~' +
            gl.getParameter(debugInfo.UNMASKED_RENDERER_WEBGL));
    }
    catch {
        return '';
    }
}
/**
 * Generate audio fingerprint
 */
function getAudioFingerprint() {
    return new Promise((resolve) => {
        try {
            const context = new (window.AudioContext ||
                window.webkitAudioContext)();
            const oscillator = context.createOscillator();
            const analyser = context.createAnalyser();
            const gainNode = context.createGain();
            const scriptProcessor = context.createScriptProcessor(4096, 1, 1);
            gainNode.gain.value = 0;
            oscillator.type = 'triangle';
            oscillator.connect(analyser);
            analyser.connect(scriptProcessor);
            scriptProcessor.connect(gainNode);
            gainNode.connect(context.destination);
            scriptProcessor.onaudioprocess = (event) => {
                const output = event.inputBuffer.getChannelData(0);
                let sum = 0;
                for (let i = 0; i < output.length; i++) {
                    sum += Math.abs(output[i]);
                }
                const fingerprint = sum.toString();
                oscillator.disconnect();
                scriptProcessor.disconnect();
                resolve(fingerprint);
            };
            oscillator.start(0);
        }
        catch {
            resolve('');
        }
    });
}
/**
 * Collect all fingerprint data
 */
async function collectFingerprint() {
    const fingerprint = {
        canvas: getCanvasFingerprint(),
        webgl: getWebGLFingerprint(),
        screenSize: {
            width: window.screen.width,
            height: window.screen.height,
        },
        timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
    };
    fingerprint.audio = await getAudioFingerprint();
    return fingerprint;
}
/**
 * Send fingerprint to server via headers
 */
async function sendFingerprintHeaders() {
    const fingerprint = await collectFingerprint();
    // Set custom headers for fetch requests
    const originalFetch = window.fetch;
    window.fetch = function (input, init) {
        const headers = new Headers(init?.headers);
        headers.set('X-Screen-Width', fingerprint.screenSize.width.toString());
        headers.set('X-Screen-Height', fingerprint.screenSize.height.toString());
        headers.set('X-Timezone', fingerprint.timezone);
        if (fingerprint.canvas) {
            headers.set('X-Canvas-Fingerprint', fingerprint.canvas.substring(0, 100));
        }
        if (fingerprint.webgl) {
            headers.set('X-WebGL-Fingerprint', fingerprint.webgl.substring(0, 100));
        }
        if (fingerprint.audio) {
            headers.set('X-Audio-Fingerprint', fingerprint.audio.substring(0, 50));
        }
        return originalFetch(input, {
            ...init,
            headers,
        });
    };
}
// Auto-initialize on load
if (typeof window !== 'undefined') {
    sendFingerprintHeaders();
}
