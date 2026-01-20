/**
 * Client-Side Advanced Bot Detection
 * Comprehensive WebDriver and automation detection
 * Wrapped in IIFE to avoid global conflicts
 */

(function () {
    interface ClientBotSignals {
        webdriver: boolean;
        languages: string[];
        plugins: number;
        mimeTypes: number;
        hardwareConcurrency: number;
        deviceMemory: number;
        maxTouchPoints: number;
        selenium: boolean;
        phantomjs: boolean;
        nightmare: boolean;
        puppeteer: boolean;
        playwright: boolean;
        cdpRuntime: boolean;
        cdpDebugger: boolean;
        hasChrome: boolean;
        chromeRuntime: boolean;
        notificationPermission: string;
        outerWidth: number;
        outerHeight: number;
        innerWidth: number;
        innerHeight: number;
        webglVendor: string;
        webglRenderer: string;
        functionToStringIntact: boolean;
        permissionsQuery: boolean;
        isIframe: boolean;
        errorStackIntact: boolean;
    }

    async function detectBotSignals(): Promise<ClientBotSignals> {
        const nav = navigator as any;
        const win = window as any;

        const webdriver = !!(
            nav.webdriver ||
            win.navigator.webdriver ||
            win.callPhantom ||
            win._phantom ||
            win.__nightmare ||
            win.domAutomation ||
            win.domAutomationController ||
            win.Cypress ||
            document.documentElement.getAttribute('webdriver') !== null
        );

        const selenium = !!(
            win._selenium ||
            win.callSelenium ||
            win._Selenium_IDE_Recorder ||
            win.__webdriver_script_fn ||
            win.__driver_evaluate ||
            win.__webdriver_evaluate ||
            win.__selenium_evaluate ||
            win.__fxdriver_evaluate ||
            win.__driver_unwrapped ||
            document.documentElement.getAttribute('selenium') !== null
        );

        const phantomjs = !!(win.callPhantom || win._phantom || win.phantom);
        const nightmare = !!win.__nightmare;
        const puppeteer = !!(win.__puppeteer__ || nav.userAgent.includes('HeadlessChrome'));
        const playwright = !!(win.__playwright || win._playwright);

        let cdpRuntime = false;
        let cdpDebugger = false;
        try {
            cdpRuntime = !!(win.cdc_adoQpoasnfa76pfcZLmcfl_Array ||
                win.cdc_adoQpoasnfa76pfcZLmcfl_Promise);
            const start = performance.now();
            debugger;
            cdpDebugger = (performance.now() - start) > 100;
        } catch { }

        const hasChrome = /Chrome/.test(nav.userAgent);
        let chromeRuntime = false;
        try { chromeRuntime = !!(win.chrome && win.chrome.runtime); } catch { }

        let notificationPermission = 'default';
        try { notificationPermission = Notification.permission; } catch { }

        let functionToStringIntact = true;
        try {
            const fnStr = Function.prototype.toString.toString();
            functionToStringIntact = fnStr.includes('[native code]');
        } catch { functionToStringIntact = false; }

        let permissionsQuery = false;
        try {
            await navigator.permissions.query({ name: 'notifications' as PermissionName });
            permissionsQuery = true;
        } catch { }

        let errorStackIntact = true;
        try {
            const err = new Error();
            errorStackIntact = err.stack !== undefined && err.stack.length > 0;
        } catch { errorStackIntact = false; }

        let webglVendor = '';
        let webglRenderer = '';
        try {
            const canvas = document.createElement('canvas');
            const gl = canvas.getContext('webgl') as WebGLRenderingContext;
            if (gl) {
                const dbg = gl.getExtension('WEBGL_debug_renderer_info');
                if (dbg) {
                    webglVendor = gl.getParameter(dbg.UNMASKED_VENDOR_WEBGL) || '';
                    webglRenderer = gl.getParameter(dbg.UNMASKED_RENDERER_WEBGL) || '';
                }
            }
        } catch { }

        return {
            webdriver,
            languages: Array.from(nav.languages || []),
            plugins: nav.plugins?.length || 0,
            mimeTypes: nav.mimeTypes?.length || 0,
            hardwareConcurrency: nav.hardwareConcurrency || 0,
            deviceMemory: nav.deviceMemory || 0,
            maxTouchPoints: nav.maxTouchPoints || 0,
            selenium,
            phantomjs,
            nightmare,
            puppeteer,
            playwright,
            cdpRuntime,
            cdpDebugger,
            hasChrome,
            chromeRuntime,
            notificationPermission,
            outerWidth: win.outerWidth,
            outerHeight: win.outerHeight,
            innerWidth: win.innerWidth,
            innerHeight: win.innerHeight,
            webglVendor,
            webglRenderer,
            functionToStringIntact,
            permissionsQuery,
            isIframe: win.self !== win.top,
            errorStackIntact,
        };
    }

    (window as any).detectBotSignals = detectBotSignals;
})();
