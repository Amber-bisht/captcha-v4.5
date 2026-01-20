export interface CSRFToken {
  token: string;
  expiresAt: number;
}

export interface CSRFVerificationResult {
  valid: boolean;
  error?: string;
}
