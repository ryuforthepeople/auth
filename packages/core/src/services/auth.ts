import type { AuthAdapter } from '../adapters/adapter.js';
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
import { AuthModuleError } from '../types/index.js';

const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const MIN_PASSWORD_LENGTH = 8;

/**
 * AuthService - orchestration layer over an AuthAdapter
 * Adds validation, normalization, and convenience methods
 */
export class AuthService {
  private adapter: AuthAdapter;

  constructor(adapter: AuthAdapter) {
    this.adapter = adapter;
  }

  /** Get the underlying provider name */
  get provider(): string {
    return this.adapter.provider;
  }

  /** Get adapter capabilities */
  getCapabilities(): AuthCapabilities {
    return this.adapter.getCapabilities();
  }

  /** Check if a specific feature is available */
  hasFeature(feature: keyof AuthCapabilities['features']): boolean {
    return this.adapter.getCapabilities().features[feature];
  }

  /** Check if a specific OAuth provider is supported */
  hasOAuthProvider(provider: OAuthProvider): boolean {
    const caps = this.adapter.getCapabilities();
    return caps.oauth.supported && caps.oauth.providers.includes(provider);
  }

  /** Check if MFA is supported */
  hasMFA(): boolean {
    return this.adapter.getCapabilities().mfa.supported;
  }

  // ─────────────────────────────────────────────────────────────────
  // Core authentication with validation
  // ─────────────────────────────────────────────────────────────────

  async signUp(options: SignUpOptions): Promise<AuthResult> {
    // Validate email
    const email = options.email.trim().toLowerCase();
    if (!EMAIL_REGEX.test(email)) {
      return {
        user: null,
        session: null,
        error: {
          code: 'INVALID_EMAIL',
          message: 'Invalid email format',
          status: 400,
        },
      };
    }

    // Validate password
    if (options.password.length < MIN_PASSWORD_LENGTH) {
      return {
        user: null,
        session: null,
        error: {
          code: 'WEAK_PASSWORD',
          message: `Password must be at least ${MIN_PASSWORD_LENGTH} characters`,
          status: 400,
        },
      };
    }

    return this.adapter.signUp({
      ...options,
      email, // normalized
    });
  }

  async signIn(options: SignInOptions): Promise<AuthResult> {
    // Normalize email if provided
    const normalizedOptions: SignInOptions = { ...options };
    if (options.email) {
      normalizedOptions.email = options.email.trim().toLowerCase();
    }

    // Validate that we have credentials
    if (!options.password && !options.provider) {
      return {
        user: null,
        session: null,
        error: {
          code: 'MISSING_CREDENTIALS',
          message: 'Must provide password or OAuth provider',
          status: 400,
        },
      };
    }

    if (options.password && !options.email && !options.phone) {
      return {
        user: null,
        session: null,
        error: {
          code: 'MISSING_IDENTIFIER',
          message: 'Must provide email or phone with password',
          status: 400,
        },
      };
    }

    return this.adapter.signIn(normalizedOptions);
  }

  async signOut(): Promise<void> {
    return this.adapter.signOut();
  }

  // ─────────────────────────────────────────────────────────────────
  // Session management
  // ─────────────────────────────────────────────────────────────────

  async getSession(): Promise<Session | null> {
    return this.adapter.getSession();
  }

  async refreshSession(): Promise<Session | null> {
    const caps = this.adapter.getCapabilities();
    if (!caps.sessions.refreshSupported) {
      throw new AuthModuleError(
        'REFRESH_NOT_SUPPORTED',
        'Session refresh is not supported by this provider',
        501
      );
    }
    return this.adapter.refreshSession();
  }

  async getUser(): Promise<User | null> {
    return this.adapter.getUser();
  }

  /** Convenience: check if user is currently authenticated */
  async isAuthenticated(): Promise<boolean> {
    const session = await this.adapter.getSession();
    if (!session) return false;
    // Check if session is expired
    return session.expiresAt > Math.floor(Date.now() / 1000);
  }

  /** Convenience: require authentication or throw */
  async requireAuth(): Promise<Session> {
    const session = await this.adapter.getSession();
    if (!session) {
      throw new AuthModuleError('NOT_AUTHENTICATED', 'Authentication required', 401);
    }
    if (session.expiresAt <= Math.floor(Date.now() / 1000)) {
      throw new AuthModuleError('SESSION_EXPIRED', 'Session has expired', 401);
    }
    return session;
  }

  // ─────────────────────────────────────────────────────────────────
  // OAuth
  // ─────────────────────────────────────────────────────────────────

  async signInWithOAuth(
    provider: OAuthProvider,
    options?: { redirectTo?: string; scopes?: string }
  ): Promise<{ url: string }> {
    if (!this.hasOAuthProvider(provider)) {
      throw new AuthModuleError(
        'OAUTH_PROVIDER_NOT_SUPPORTED',
        `OAuth provider '${provider}' is not supported`,
        400
      );
    }
    return this.adapter.signInWithOAuth(provider, options);
  }

  async handleOAuthCallback(params: URLSearchParams): Promise<AuthResult> {
    return this.adapter.handleOAuthCallback(params);
  }

  // ─────────────────────────────────────────────────────────────────
  // Password management
  // ─────────────────────────────────────────────────────────────────

  async resetPassword(email: string, redirectTo?: string): Promise<void> {
    if (!this.hasFeature('passwordReset')) {
      throw new AuthModuleError(
        'PASSWORD_RESET_NOT_SUPPORTED',
        'Password reset is not supported by this provider',
        501
      );
    }

    const normalizedEmail = email.trim().toLowerCase();
    if (!EMAIL_REGEX.test(normalizedEmail)) {
      throw new AuthModuleError('INVALID_EMAIL', 'Invalid email format', 400);
    }

    return this.adapter.resetPassword(normalizedEmail, redirectTo);
  }

  async updatePassword(newPassword: string): Promise<void> {
    if (newPassword.length < MIN_PASSWORD_LENGTH) {
      throw new AuthModuleError(
        'WEAK_PASSWORD',
        `Password must be at least ${MIN_PASSWORD_LENGTH} characters`,
        400
      );
    }
    return this.adapter.updatePassword(newPassword);
  }

  // ─────────────────────────────────────────────────────────────────
  // MFA
  // ─────────────────────────────────────────────────────────────────

  async enrollMFA(method: MFAMethod): Promise<MFAEnrollment> {
    const caps = this.adapter.getCapabilities();
    if (!caps.mfa.supported) {
      throw new AuthModuleError('MFA_NOT_SUPPORTED', 'MFA is not supported by this provider', 501);
    }
    if (!caps.mfa.methods.includes(method)) {
      throw new AuthModuleError(
        'MFA_METHOD_NOT_SUPPORTED',
        `MFA method '${method}' is not supported`,
        400
      );
    }
    if (!this.adapter.enrollMFA) {
      throw new AuthModuleError('MFA_NOT_IMPLEMENTED', 'MFA enrollment not implemented', 501);
    }
    return this.adapter.enrollMFA(method);
  }

  async verifyMFA(factorId: string, code: string): Promise<AuthResult> {
    if (!this.hasMFA() || !this.adapter.verifyMFA) {
      throw new AuthModuleError('MFA_NOT_SUPPORTED', 'MFA is not supported by this provider', 501);
    }
    if (!code || code.length < 6) {
      return {
        user: null,
        session: null,
        error: {
          code: 'INVALID_MFA_CODE',
          message: 'MFA code must be at least 6 digits',
          status: 400,
        },
      };
    }
    return this.adapter.verifyMFA(factorId, code);
  }

  async unenrollMFA(factorId: string): Promise<void> {
    if (!this.hasMFA() || !this.adapter.unenrollMFA) {
      throw new AuthModuleError('MFA_NOT_SUPPORTED', 'MFA is not supported by this provider', 501);
    }
    return this.adapter.unenrollMFA(factorId);
  }

  async listMFAFactors(): Promise<MFAEnrollment[]> {
    if (!this.hasMFA() || !this.adapter.listMFAFactors) {
      return [];
    }
    return this.adapter.listMFAFactors();
  }

  // ─────────────────────────────────────────────────────────────────
  // User management
  // ─────────────────────────────────────────────────────────────────

  async updateUser(updates: Partial<Pick<User, 'email' | 'phone' | 'metadata'>>): Promise<User> {
    if (!this.adapter.updateUser) {
      throw new AuthModuleError(
        'UPDATE_USER_NOT_SUPPORTED',
        'User updates are not supported by this provider',
        501
      );
    }

    // Validate email if being updated
    if (updates.email) {
      const normalizedEmail = updates.email.trim().toLowerCase();
      if (!EMAIL_REGEX.test(normalizedEmail)) {
        throw new AuthModuleError('INVALID_EMAIL', 'Invalid email format', 400);
      }
      updates = { ...updates, email: normalizedEmail };
    }

    return this.adapter.updateUser(updates);
  }

  async deleteUser(): Promise<void> {
    if (!this.adapter.deleteUser) {
      throw new AuthModuleError(
        'DELETE_USER_NOT_SUPPORTED',
        'User deletion is not supported by this provider',
        501
      );
    }
    return this.adapter.deleteUser();
  }

  // ─────────────────────────────────────────────────────────────────
  // Real-time subscriptions
  // ─────────────────────────────────────────────────────────────────

  onAuthStateChange(callback: AuthStateChangeCallback): () => void {
    return this.adapter.onAuthStateChange(callback);
  }

  // ─────────────────────────────────────────────────────────────────
  // Admin API
  // ─────────────────────────────────────────────────────────────────

  get admin() {
    if (!this.adapter.admin) {
      return undefined;
    }
    const adapterAdmin = this.adapter.admin;

    return {
      listUsers: async (options?: { page?: number; perPage?: number }) => {
        return adapterAdmin.listUsers(options);
      },

      getUserById: async (id: string) => {
        return adapterAdmin.getUserById(id);
      },

      deleteUser: async (id: string) => {
        return adapterAdmin.deleteUser(id);
      },

      updateUser: async (
        id: string,
        updates: Partial<Pick<User, 'email' | 'phone' | 'metadata' | 'appMetadata'>>
      ) => {
        // Validate email if being updated
        if (updates.email) {
          const normalizedEmail = updates.email.trim().toLowerCase();
          if (!EMAIL_REGEX.test(normalizedEmail)) {
            throw new AuthModuleError('INVALID_EMAIL', 'Invalid email format', 400);
          }
          updates = { ...updates, email: normalizedEmail };
        }
        return adapterAdmin.updateUser(id, updates);
      },
    };
  }
}
