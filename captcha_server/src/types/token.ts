export interface TokenPayload {
  challengeId: string;
  nonce: string;
  timestamp: number;
  fingerprint: string;
  ip: string;
}

export interface TokenResponse {
  token: string;
  expiresIn: number;
}

export interface TokenVerificationResult {
  valid: boolean;
  payload?: TokenPayload;
  error?: string;
}
