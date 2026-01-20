export interface SessionData {
  challengeId?: string;
  fingerprint?: string;
  createdAt: number;
  csrfToken?: string;
}

export interface SessionConfig {
  secret: string;
  resave: boolean;
  saveUninitialized: boolean;
  cookie: {
    secure: boolean;
    httpOnly: boolean;
    maxAge: number;
    sameSite: 'strict' | 'lax' | 'none';
  };
}
