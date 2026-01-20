export interface BrowserFingerprint {
  ip: string;
  userAgent: string;
  acceptLanguage: string;
  screenSize: {
    width: number;
    height: number;
  };
  timezone: string;
  canvas?: string;
  webgl?: string;
  audio?: string;
  plugins?: string[];
}

export interface FingerprintHash {
  hash: string;
  components: BrowserFingerprint;
}
