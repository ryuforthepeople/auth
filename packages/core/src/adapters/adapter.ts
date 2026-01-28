import type {
  AuthCapabilities,
  OAuthProvider,
  MFAMethod,
  User,
  Session,
  SignUpOptions,
  SignInOptions,
  AuthResult,
  MFAEnrollment,
  AuthStateChangeCallback,
} from '../types/index.js';

/**
 * AuthAdapter interface - all auth providers must implement this
 */
export interface AuthAdapter {
  /** Provider identifier (e.g., 'supabase', 'firebase', 'auth0') */
  readonly provider: string;

  /**
   * Get adapter capabilities
   * Used by apps to know what features are available
   */
  getCapabilities(): AuthCapabilities;

  // ─────────────────────────────────────────────────────────────────
  // Core authentication
  // ─────────────────────────────────────────────────────────────────

  /** Sign up a new user with email/password */
  signUp(options: SignUpOptions): Promise<AuthResult>;

  /** Sign in an existing user */
  signIn(options: SignInOptions): Promise<AuthResult>;

  /** Sign out the current user */
  signOut(): Promise<void>;

  // ─────────────────────────────────────────────────────────────────
  // Session management
  // ─────────────────────────────────────────────────────────────────

  /** Get the current session (if any) */
  getSession(): Promise<Session | null>;

  /** Refresh the current session */
  refreshSession(): Promise<Session | null>;

  /** Get the current user (without session) */
  getUser(): Promise<User | null>;

  // ─────────────────────────────────────────────────────────────────
  // OAuth
  // ─────────────────────────────────────────────────────────────────

  /** Initiate OAuth sign-in flow */
  signInWithOAuth(
    provider: OAuthProvider,
    options?: { redirectTo?: string; scopes?: string }
  ): Promise<{ url: string }>;

  /** Handle OAuth callback (exchange code for session) */
  handleOAuthCallback(params: URLSearchParams): Promise<AuthResult>;

  // ─────────────────────────────────────────────────────────────────
  // Password management
  // ─────────────────────────────────────────────────────────────────

  /** Send password reset email */
  resetPassword(email: string, redirectTo?: string): Promise<void>;

  /** Update user's password (requires active session) */
  updatePassword(newPassword: string): Promise<void>;

  // ─────────────────────────────────────────────────────────────────
  // MFA (optional - check capabilities.mfa.supported first)
  // ─────────────────────────────────────────────────────────────────

  /** Enroll in MFA */
  enrollMFA?(method: MFAMethod): Promise<MFAEnrollment>;

  /** Verify MFA code */
  verifyMFA?(factorId: string, code: string): Promise<AuthResult>;

  /** Unenroll from MFA */
  unenrollMFA?(factorId: string): Promise<void>;

  /** List enrolled MFA factors */
  listMFAFactors?(): Promise<MFAEnrollment[]>;

  // ─────────────────────────────────────────────────────────────────
  // User management
  // ─────────────────────────────────────────────────────────────────

  /** Update user profile/metadata */
  updateUser?(updates: Partial<Pick<User, 'email' | 'phone' | 'metadata'>>): Promise<User>;

  /** Delete the current user's account */
  deleteUser?(): Promise<void>;

  // ─────────────────────────────────────────────────────────────────
  // Real-time subscriptions
  // ─────────────────────────────────────────────────────────────────

  /** Subscribe to auth state changes */
  onAuthStateChange(callback: AuthStateChangeCallback): () => void;

  // ─────────────────────────────────────────────────────────────────
  // Admin API (optional - check capabilities.features.adminAPI first)
  // ─────────────────────────────────────────────────────────────────

  admin?: {
    /** List all users with pagination */
    listUsers(options?: {
      page?: number;
      perPage?: number;
    }): Promise<{ users: User[]; total: number }>;

    /** Get a user by ID */
    getUserById(id: string): Promise<User | null>;

    /** Delete a user by ID */
    deleteUser(id: string): Promise<void>;

    /** Update a user by ID */
    updateUser(
      id: string,
      updates: Partial<Pick<User, 'email' | 'phone' | 'metadata' | 'appMetadata'>>
    ): Promise<User>;
  };
}
