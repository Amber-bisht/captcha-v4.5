export interface CaptchaConfig {
  size: number;
  ignoreChars: string;
  noise: number;
  color: boolean;
  background: string;
  fontSize?: number;
  width?: number;
  height?: number;
}

export interface CaptchaChallenge {
  id: string;
  image: string;
  text: string;
  createdAt: number;
  expiresAt: number;
}
