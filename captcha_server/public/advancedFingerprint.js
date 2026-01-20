"use strict";
/**
 * Client-Side Advanced Fingerprinting
 * 30+ browser signals for robust identification
 * Wrapped in IIFE to avoid global conflicts
 */
(function () {
    async function hashStr(str) {
        const encoder = new TextEncoder();
        const data = encoder.encode(str);
        const hashBuffer = await crypto.subtle.digest('SHA-256', data);
        const hashArray = Array.from(new Uint8Array(hashBuffer));
        return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
    }
    async function canvasHash() {
        try {
            const canvas = document.createElement('canvas');
            canvas.width = 200;
            canvas.height = 50;
            const ctx = canvas.getContext('2d');
            if (!ctx)
                return '';
            ctx.textBaseline = 'alphabetic';
            ctx.font = "14px 'Arial'";
            ctx.fillStyle = '#f60';
            ctx.fillRect(125, 1, 62, 20);
            ctx.fillStyle = '#069';
            ctx.fillText('Cwm fjordbank gly', 2, 15);
            ctx.fillStyle = 'rgba(102, 204, 0, 0.7)';
            ctx.fillText('Cwm fjordbank gly', 4, 17);
            return await hashStr(canvas.toDataURL());
        }
        catch {
            return '';
        }
    }
    function webglData() {
        try {
            const canvas = document.createElement('canvas');
            const gl = canvas.getContext('webgl');
            if (!gl)
                return { vendor: '', renderer: '', version: '', hash: '' };
            const dbg = gl.getExtension('WEBGL_debug_renderer_info');
            const vendor = dbg ? gl.getParameter(dbg.UNMASKED_VENDOR_WEBGL) : '';
            const renderer = dbg ? gl.getParameter(dbg.UNMASKED_RENDERER_WEBGL) : '';
            const version = gl.getParameter(gl.VERSION);
            return { vendor, renderer, version, hash: btoa(vendor + renderer + version).slice(0, 32) };
        }
        catch {
            return { vendor: '', renderer: '', version: '', hash: '' };
        }
    }
    async function audioHash() {
        try {
            const ctx = new (window.AudioContext || window.webkitAudioContext)();
            const osc = ctx.createOscillator();
            const analyser = ctx.createAnalyser();
            const gain = ctx.createGain();
            const proc = ctx.createScriptProcessor(4096, 1, 1);
            gain.gain.value = 0;
            osc.type = 'triangle';
            osc.connect(analyser);
            analyser.connect(proc);
            proc.connect(gain);
            gain.connect(ctx.destination);
            osc.start(0);
            const fp = await new Promise((res) => {
                proc.onaudioprocess = (e) => {
                    const d = e.inputBuffer.getChannelData(0);
                    const sum = d.reduce((a, b) => a + Math.abs(b), 0);
                    osc.disconnect();
                    res(sum.toString());
                };
            });
            ctx.close();
            return await hashStr(fp);
        }
        catch {
            return '';
        }
    }
    async function fontsHash() {
        const fonts = ['Arial', 'Verdana', 'Times New Roman', 'Courier New', 'Georgia'];
        const detected = [];
        const testStr = 'mmmmmmmmmmlli';
        const measure = (font) => {
            const span = document.createElement('span');
            span.style.cssText = `position:absolute;left:-9999px;font-size:72px;font-family:${font}`;
            span.textContent = testStr;
            document.body.appendChild(span);
            const w = span.offsetWidth;
            document.body.removeChild(span);
            return w;
        };
        const baseWidth = measure('monospace');
        for (const f of fonts) {
            if (measure(`'${f}', monospace`) !== baseWidth)
                detected.push(f);
        }
        return await hashStr(detected.join(','));
    }
    async function webrtcIPs() {
        const ips = [];
        try {
            const pc = new RTCPeerConnection({ iceServers: [] });
            pc.createDataChannel('');
            await pc.createOffer().then(o => pc.setLocalDescription(o));
            await new Promise((res) => {
                const tm = setTimeout(res, 1000);
                pc.onicecandidate = (e) => {
                    if (!e.candidate) {
                        clearTimeout(tm);
                        res();
                        return;
                    }
                    const m = e.candidate.candidate.match(/([0-9]{1,3}\.){3}[0-9]{1,3}/);
                    if (m && !ips.includes(m[0]))
                        ips.push(m[0]);
                };
            });
            pc.close();
        }
        catch { }
        return ips;
    }
    function detectLies() {
        const nav = navigator;
        const ua = nav.userAgent.toLowerCase();
        return {
            languages: nav.language && !nav.languages?.includes(nav.language),
            resolution: screen.width < screen.availWidth || screen.height < screen.availHeight,
            os: (ua.includes('windows') && nav.platform !== 'Win32' && nav.platform !== 'Win64') ||
                (ua.includes('mac') && !nav.platform.includes('Mac')),
            browser: (ua.includes('chrome') && !window.chrome),
        };
    }
    async function generateAdvancedFingerprint() {
        const nav = navigator;
        const ch = await canvasHash();
        const wgl = webglData();
        const ah = await audioHash();
        const fh = await fontsHash();
        const plugins = Array.from(nav.plugins || []).map((p) => p.name).join(',');
        const ph = await hashStr(plugins);
        const rtcIPs = await webrtcIPs();
        const lies = detectLies();
        return {
            userAgent: nav.userAgent,
            language: nav.language,
            languages: Array.from(nav.languages || []),
            platform: nav.platform,
            hardwareConcurrency: nav.hardwareConcurrency || 0,
            deviceMemory: nav.deviceMemory || 0,
            maxTouchPoints: nav.maxTouchPoints || 0,
            screenWidth: screen.width,
            screenHeight: screen.height,
            screenColorDepth: screen.colorDepth,
            availWidth: screen.availWidth,
            availHeight: screen.availHeight,
            devicePixelRatio: window.devicePixelRatio,
            timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
            timezoneOffset: new Date().getTimezoneOffset(),
            canvasHash: ch,
            webglVendor: wgl.vendor,
            webglRenderer: wgl.renderer,
            webglVersion: wgl.version,
            webglHash: wgl.hash,
            audioHash: ah,
            fontsHash: fh,
            pluginsHash: ph,
            pluginCount: nav.plugins?.length || 0,
            cookiesEnabled: nav.cookieEnabled,
            doNotTrack: nav.doNotTrack,
            localStorage: !!window.localStorage,
            sessionStorage: !!window.sessionStorage,
            indexedDB: !!window.indexedDB,
            webrtcLocalIPs: rtcIPs,
            hasLiedLanguages: !!lies.languages,
            hasLiedResolution: lies.resolution,
            hasLiedOs: lies.os,
            hasLiedBrowser: lies.browser,
        };
    }
    window.generateAdvancedFingerprint = generateAdvancedFingerprint;
})();
