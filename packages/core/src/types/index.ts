export * from './capabilities.js';
export type { OAuthProvider, MFAMethod, SessionType, AuthCapabilities } from './capabilities.js';

/** Authenticated user */
export interface User {
  id: string;
  email: string;
  phone?: string;
  emailVerified: boolean;
  phoneVerified: boolean;
  createdAt: string;
  updatedAt: string;
  lastSignInAt?: string;
  metadata?: Record<string, unknown>;
  appMetadata?: Record<string, unknown>;
}

/** Session with tokens and user */
export interface Session {
  accessToken: string;
  refreshToken?: string;
  expiresAt: number;
  user: User;
}

/** Options for signing up */
export interface SignUpOptions {
  email: string;
  password: string;
  phone?: string;
  metadata?: Record<string, unknown>;
  redirectTo?: string;
}

/** Options for signing in */
export interface SignInOptions {
  email?: string;
  phone?: string;
  password?: string;
  provider?: import('./capabilities.js').OAuthProvider;
  redirectTo?: string;
}

/** Result of auth operations */
export interface AuthResult {
  user: User | null;
  session: Session | null;
  error?: AuthError;
}

/** Auth error details */
export interface AuthError {
  code: string;
  message: string;
  status: number;
}

/** MFA enrollment information */
export interface MFAEnrollment {
  id: string;
  type: import('./capabilities.js').MFAMethod;
  totpSecret?: string;
  totpUri?: string;
  phone?: string;
}

/** Auth state change events */
export type AuthStateEvent =
  | 'SIGNED_IN'
  | 'SIGNED_OUT'
  | 'TOKEN_REFRESHED'
  | 'USER_UPDATED';

/** Callback for auth state changes */
export interface AuthStateChangeCallback {
  (event: AuthStateEvent, session: Session | null): void;
}

/** Supabase adapter configuration */
export interface SupabaseAuthConfig {
  url: string;
  anonKey: string;
  serviceRoleKey?: string;
}

/** Class for auth errors */
export class AuthModuleError extends Error {
  readonly code: string;
  readonly status: number;

  constructor(code: string, message: string, status: number = 500) {
    super(message);
    this.name = 'AuthModuleError';
    this.code = code;
    this.status = status;
  }

  toAuthError(): AuthError {
    return {
      code: this.code,
      message: this.message,
      status: this.status,
    };
  }
}
