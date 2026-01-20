import session from 'express-session';
import crypto from 'crypto';
import { SessionConfig } from '../types/session';

const SESSION_SECRET =
  process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex');
const SESSION_MAX_AGE = 10 * 60 * 1000; // 10 minutes

export const sessionConfig: SessionConfig = {
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: process.env.NODE_ENV === 'production',
    httpOnly: true,
    maxAge: SESSION_MAX_AGE,
    sameSite: 'strict',
  },
};

export function createSessionMiddleware() {
  return session(sessionConfig);
}
