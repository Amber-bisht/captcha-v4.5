/**
 * Advanced Bot Detection System
 * Comprehensive WebDriver and automation framework detection
 */

export interface BotDetectionResult {
  isBot: boolean;
  confidence: number; // 0-100
  signals: BotSignal[];
  riskLevel: 'low' | 'medium' | 'high' | 'critical';
}

export interface BotSignal {
  name: string;
  detected: boolean;
  weight: number;
  description: string;
}

export interface ClientBotSignals {
  // Navigator properties
  webdriver?: boolean;
  languages?: string[];
  plugins?: number;
  mimeTypes?: number;
  hardwareConcurrency?: number;
  deviceMemory?: number;
  maxTouchPoints?: number;
  
  // Automation indicators
  selenium?: boolean;
  phantomjs?: boolean;
  nightmare?: boolean;
  puppeteer?: boolean;
  playwright?: boolean;
  
  // CDP (Chrome DevTools Protocol) detection
  cdpRuntime?: boolean;
  cdpDebugger?: boolean;
  
  // Browser inconsistencies
  hasChrome?: boolean;
  chromeRuntime?: boolean;
  notificationPermission?: string;
  
  // Window properties
  outerWidth?: number;
  outerHeight?: number;
  innerWidth?: number;
  innerHeight?: number;
  
  // WebGL anomalies
  webglVendor?: string;
  webglRenderer?: string;
  
  // Timing anomalies
  performanceNow?: number;
  dateNow?: number;
  
  // Function detection
  functionToStringIntact?: boolean;
  
  // Permission anomalies
  permissionsQuery?: boolean;
  
  // iframe detection
  isIframe?: boolean;
  
  // Error handling
  errorStackIntact?: boolean;
}

export class AdvancedBotDetector {
  private static readonly DETECTION_WEIGHTS = {
    webdriver: 40,
    selenium: 35,
    puppeteer: 35,
    playwright: 35,
    phantomjs: 30,
    nightmare: 30,
    cdpRuntime: 25,
    cdpDebugger: 25,
    noPlugins: 15,
    noMimeTypes: 15,
    zeroHardwareConcurrency: 20,
    lowDeviceMemory: 10,
    chromeWithoutRuntime: 20,
    headlessUserAgent: 35,
    automationUserAgent: 35,
    missingHeaders: 15,
    suspiciousWebGL: 20,
    functionTampered: 25,
    permissionsDenied: 10,
    windowSizeAnomaly: 15,
    iframeEmbed: 5,
    errorStackTampered: 15,
    missingLanguages: 10,
    touchWithoutMobile: 10,
  };

  /**
   * Analyze client-side bot signals
   */
  static analyzeClientSignals(signals: ClientBotSignals): BotDetectionResult {
    const detectedSignals: BotSignal[] = [];
    let totalScore = 0;

    // WebDriver detection (most critical)
    if (signals.webdriver === true) {
      detectedSignals.push({
        name: 'webdriver',
        detected: true,
        weight: this.DETECTION_WEIGHTS.webdriver,
        description: 'navigator.webdriver is true',
      });
      totalScore += this.DETECTION_WEIGHTS.webdriver;
    }

    // Selenium detection
    if (signals.selenium) {
      detectedSignals.push({
        name: 'selenium',
        detected: true,
        weight: this.DETECTION_WEIGHTS.selenium,
        description: 'Selenium automation detected',
      });
      totalScore += this.DETECTION_WEIGHTS.selenium;
    }

    // Puppeteer detection
    if (signals.puppeteer) {
      detectedSignals.push({
        name: 'puppeteer',
        detected: true,
        weight: this.DETECTION_WEIGHTS.puppeteer,
        description: 'Puppeteer automation detected',
      });
      totalScore += this.DETECTION_WEIGHTS.puppeteer;
    }

    // Playwright detection
    if (signals.playwright) {
      detectedSignals.push({
        name: 'playwright',
        detected: true,
        weight: this.DETECTION_WEIGHTS.playwright,
        description: 'Playwright automation detected',
      });
      totalScore += this.DETECTION_WEIGHTS.playwright;
    }

    // PhantomJS detection
    if (signals.phantomjs) {
      detectedSignals.push({
        name: 'phantomjs',
        detected: true,
        weight: this.DETECTION_WEIGHTS.phantomjs,
        description: 'PhantomJS detected',
      });
      totalScore += this.DETECTION_WEIGHTS.phantomjs;
    }

    // CDP Runtime detection
    if (signals.cdpRuntime) {
      detectedSignals.push({
        name: 'cdpRuntime',
        detected: true,
        weight: this.DETECTION_WEIGHTS.cdpRuntime,
        description: 'Chrome DevTools Protocol runtime detected',
      });
      totalScore += this.DETECTION_WEIGHTS.cdpRuntime;
    }

    // CDP Debugger detection
    if (signals.cdpDebugger) {
      detectedSignals.push({
        name: 'cdpDebugger',
        detected: true,
        weight: this.DETECTION_WEIGHTS.cdpDebugger,
        description: 'Chrome DevTools Protocol debugger detected',
      });
      totalScore += this.DETECTION_WEIGHTS.cdpDebugger;
    }

    // No plugins (suspicious in non-mobile)
    if (signals.plugins === 0) {
      detectedSignals.push({
        name: 'noPlugins',
        detected: true,
        weight: this.DETECTION_WEIGHTS.noPlugins,
        description: 'No browser plugins detected',
      });
      totalScore += this.DETECTION_WEIGHTS.noPlugins;
    }

    // No MIME types
    if (signals.mimeTypes === 0) {
      detectedSignals.push({
        name: 'noMimeTypes',
        detected: true,
        weight: this.DETECTION_WEIGHTS.noMimeTypes,
        description: 'No MIME types detected',
      });
      totalScore += this.DETECTION_WEIGHTS.noMimeTypes;
    }

    // Zero hardware concurrency
    if (signals.hardwareConcurrency === 0) {
      detectedSignals.push({
        name: 'zeroHardwareConcurrency',
        detected: true,
        weight: this.DETECTION_WEIGHTS.zeroHardwareConcurrency,
        description: 'Hardware concurrency is 0',
      });
      totalScore += this.DETECTION_WEIGHTS.zeroHardwareConcurrency;
    }

    // Chrome without runtime
    if (signals.hasChrome && !signals.chromeRuntime) {
      detectedSignals.push({
        name: 'chromeWithoutRuntime',
        detected: true,
        weight: this.DETECTION_WEIGHTS.chromeWithoutRuntime,
        description: 'Chrome browser without chrome.runtime',
      });
      totalScore += this.DETECTION_WEIGHTS.chromeWithoutRuntime;
    }

    // Function.prototype.toString tampered
    if (signals.functionToStringIntact === false) {
      detectedSignals.push({
        name: 'functionTampered',
        detected: true,
        weight: this.DETECTION_WEIGHTS.functionTampered,
        description: 'Function.prototype.toString has been tampered',
      });
      totalScore += this.DETECTION_WEIGHTS.functionTampered;
    }

    // Window size anomaly (matching inner/outer)
    if (signals.outerWidth === signals.innerWidth && signals.outerHeight === signals.innerHeight) {
      detectedSignals.push({
        name: 'windowSizeAnomaly',
        detected: true,
        weight: this.DETECTION_WEIGHTS.windowSizeAnomaly,
        description: 'Window inner/outer dimensions match exactly',
      });
      totalScore += this.DETECTION_WEIGHTS.windowSizeAnomaly;
    }

    // Error stack tampered
    if (signals.errorStackIntact === false) {
      detectedSignals.push({
        name: 'errorStackTampered',
        detected: true,
        weight: this.DETECTION_WEIGHTS.errorStackTampered,
        description: 'Error stack has been modified',
      });
      totalScore += this.DETECTION_WEIGHTS.errorStackTampered;
    }

    // Missing languages
    if (!signals.languages || signals.languages.length === 0) {
      detectedSignals.push({
        name: 'missingLanguages',
        detected: true,
        weight: this.DETECTION_WEIGHTS.missingLanguages,
        description: 'No navigator languages',
      });
      totalScore += this.DETECTION_WEIGHTS.missingLanguages;
    }

    // Calculate confidence and risk level
    const confidence = Math.min(totalScore, 100);
    let riskLevel: 'low' | 'medium' | 'high' | 'critical';

    if (confidence >= 70) {
      riskLevel = 'critical';
    } else if (confidence >= 50) {
      riskLevel = 'high';
    } else if (confidence >= 25) {
      riskLevel = 'medium';
    } else {
      riskLevel = 'low';
    }

    return {
      isBot: confidence >= 40,
      confidence,
      signals: detectedSignals,
      riskLevel,
    };
  }

  /**
   * Analyze server-side signals (headers, etc.)
   */
  static analyzeServerSignals(
    userAgent: string,
    headers: Record<string, string | string[] | undefined>
  ): BotDetectionResult {
    const detectedSignals: BotSignal[] = [];
    let totalScore = 0;

    const uaLower = userAgent.toLowerCase();

    // Headless browser in UA
    const headlessPatterns = ['headless', 'headlesschrome', 'phantomjs', 'electron'];
    for (const pattern of headlessPatterns) {
      if (uaLower.includes(pattern)) {
        detectedSignals.push({
          name: 'headlessUserAgent',
          detected: true,
          weight: this.DETECTION_WEIGHTS.headlessUserAgent,
          description: `Headless browser pattern "${pattern}" in User-Agent`,
        });
        totalScore += this.DETECTION_WEIGHTS.headlessUserAgent;
        break;
      }
    }

    // Automation frameworks in UA
    const automationPatterns = ['selenium', 'webdriver', 'puppeteer', 'playwright', 'nightmare'];
    for (const pattern of automationPatterns) {
      if (uaLower.includes(pattern)) {
        detectedSignals.push({
          name: 'automationUserAgent',
          detected: true,
          weight: this.DETECTION_WEIGHTS.automationUserAgent,
          description: `Automation pattern "${pattern}" in User-Agent`,
        });
        totalScore += this.DETECTION_WEIGHTS.automationUserAgent;
        break;
      }
    }

    // Missing essential headers
    const essentialHeaders = ['accept-language', 'accept-encoding', 'accept'];
    let missingCount = 0;
    for (const header of essentialHeaders) {
      if (!headers[header]) {
        missingCount++;
      }
    }
    if (missingCount >= 2) {
      detectedSignals.push({
        name: 'missingHeaders',
        detected: true,
        weight: this.DETECTION_WEIGHTS.missingHeaders * missingCount,
        description: `Missing ${missingCount} essential headers`,
      });
      totalScore += this.DETECTION_WEIGHTS.missingHeaders * missingCount;
    }

    // Suspicious WebGL (if provided in headers)
    const webglRenderer = headers['x-webgl-renderer'] as string | undefined;
    if (webglRenderer) {
      const suspiciousRenderers = ['swiftshader', 'llvmpipe', 'mesa', 'virtualbox'];
      for (const suspicious of suspiciousRenderers) {
        if (webglRenderer.toLowerCase().includes(suspicious)) {
          detectedSignals.push({
            name: 'suspiciousWebGL',
            detected: true,
            weight: this.DETECTION_WEIGHTS.suspiciousWebGL,
            description: `Suspicious WebGL renderer: ${suspicious}`,
          });
          totalScore += this.DETECTION_WEIGHTS.suspiciousWebGL;
          break;
        }
      }
    }

    // Calculate confidence and risk level
    const confidence = Math.min(totalScore, 100);
    let riskLevel: 'low' | 'medium' | 'high' | 'critical';

    if (confidence >= 70) {
      riskLevel = 'critical';
    } else if (confidence >= 50) {
      riskLevel = 'high';
    } else if (confidence >= 25) {
      riskLevel = 'medium';
    } else {
      riskLevel = 'low';
    }

    return {
      isBot: confidence >= 40,
      confidence,
      signals: detectedSignals,
      riskLevel,
    };
  }

  /**
   * Combine client and server signals for final verdict
   */
  static combineResults(
    clientResult: BotDetectionResult | null,
    serverResult: BotDetectionResult
  ): BotDetectionResult {
    if (!clientResult) {
      return serverResult;
    }

    const allSignals = [...clientResult.signals, ...serverResult.signals];
    const combinedConfidence = Math.min(
      clientResult.confidence + serverResult.confidence,
      100
    );

    let riskLevel: 'low' | 'medium' | 'high' | 'critical';
    if (combinedConfidence >= 70) {
      riskLevel = 'critical';
    } else if (combinedConfidence >= 50) {
      riskLevel = 'high';
    } else if (combinedConfidence >= 25) {
      riskLevel = 'medium';
    } else {
      riskLevel = 'low';
    }

    return {
      isBot: combinedConfidence >= 35,
      confidence: combinedConfidence,
      signals: allSignals,
      riskLevel,
    };
  }
}
