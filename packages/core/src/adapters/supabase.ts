import {
  createClient,
  type SupabaseClient,
  type AuthChangeEvent,
} from '@supabase/supabase-js';
import type { AuthAdapter } from './adapter.js';
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
  AuthStateEvent,
  SupabaseAuthConfig,
} from '../types/index.js';
import { AuthModuleError } from '../types/index.js';

/** Map Supabase user to our User type */
function mapUser(supabaseUser: { 
  id: string;
  email?: string;
  phone?: string;
  email_confirmed_at?: string | null;
  phone_confirmed_at?: string | null;
  created_at?: string;
  updated_at?: string;
  last_sign_in_at?: string | null;
  user_metadata?: Record<string, unknown>;
  app_metadata?: Record<string, unknown>;
}): User {
  return {
    id: supabaseUser.id,
    email: supabaseUser.email ?? '',
    phone: supabaseUser.phone,
    emailVerified: !!supabaseUser.email_confirmed_at,
    phoneVerified: !!supabaseUser.phone_confirmed_at,
    createdAt: supabaseUser.created_at ?? new Date().toISOString(),
    updatedAt: supabaseUser.updated_at ?? new Date().toISOString(),
    lastSignInAt: supabaseUser.last_sign_in_at ?? undefined,
    metadata: supabaseUser.user_metadata,
    appMetadata: supabaseUser.app_metadata,
  };
}

/** Map Supabase session to our Session type */
function mapSession(supabaseSession: {
  access_token: string;
  refresh_token?: string;
  expires_at?: number;
  user: Parameters<typeof mapUser>[0];
}): Session {
  return {
    accessToken: supabaseSession.access_token,
    refreshToken: supabaseSession.refresh_token,
    expiresAt: supabaseSession.expires_at ?? Math.floor(Date.now() / 1000) + 3600,
    user: mapUser(supabaseSession.user),
  };
}

/** Map Supabase auth events to our events */
function mapAuthEvent(event: AuthChangeEvent): AuthStateEvent | null {
  switch (event) {
    case 'SIGNED_IN':
    case 'INITIAL_SESSION':
      return 'SIGNED_IN';
    case 'SIGNED_OUT':
      return 'SIGNED_OUT';
    case 'TOKEN_REFRESHED':
      return 'TOKEN_REFRESHED';
    case 'USER_UPDATED':
      return 'USER_UPDATED';
    default:
      return null;
  }
}

/**
 * Supabase Auth Adapter
 * Implements AuthAdapter using Supabase Auth
 */
export class SupabaseAuthAdapter implements AuthAdapter {
  readonly provider = 'supabase';
  private client: SupabaseClient;
  private adminClient?: SupabaseClient;

  constructor(config: SupabaseAuthConfig) {
    this.client = createClient(config.url, config.anonKey);
    if (config.serviceRoleKey) {
      this.adminClient = createClient(config.url, config.serviceRoleKey, {
        auth: { autoRefreshToken: false, persistSession: false },
      });
    }
  }

  getCapabilities(): AuthCapabilities {
    return {
      provider: 'supabase',
      version: '2.x',
      oauth: {
        supported: true,
        providers: [
          'google',
          'apple',
          'github',
          'facebook',
          'twitter',
          'discord',
          'linkedin',
          'microsoft',
        ],
      },
      mfa: {
        supported: true,
        methods: ['totp'],
        required: false,
      },
      sessions: {
        type: 'jwt',
        refreshSupported: true,
        maxAgeSeconds: 3600,
      },
      features: {
        passwordless: true,
        magicLink: true,
        phoneAuth: true,
        emailVerification: true,
        passwordReset: true,
        userMetadata: true,
        adminAPI: !!this.adminClient,
      },
    };
  }

  // ─────────────────────────────────────────────────────────────────
  // Core authentication
  // ─────────────────────────────────────────────────────────────────

  async signUp(options: SignUpOptions): Promise<AuthResult> {
    const { data, error } = await this.client.auth.signUp({
      email: options.email,
      password: options.password,
      phone: options.phone,
      options: {
        data: options.metadata,
        emailRedirectTo: options.redirectTo,
      },
    });

    if (error) {
      return {
        user: null,
        session: null,
        error: {
          code: error.code ?? 'SIGNUP_ERROR',
          message: error.message,
          status: error.status ?? 400,
        },
      };
    }

    return {
      user: data.user ? mapUser(data.user) : null,
      session: data.session ? mapSession(data.session) : null,
    };
  }

  async signIn(options: SignInOptions): Promise<AuthResult> {
    // Email/password sign in
    if (options.email && options.password) {
      const { data, error } = await this.client.auth.signInWithPassword({
        email: options.email,
        password: options.password,
      });

      if (error) {
        return {
          user: null,
          session: null,
          error: {
            code: error.code ?? 'SIGNIN_ERROR',
            message: error.message,
            status: error.status ?? 401,
          },
        };
      }

      return {
        user: data.user ? mapUser(data.user) : null,
        session: data.session ? mapSession(data.session) : null,
      };
    }

    // Phone/password sign in
    if (options.phone && options.password) {
      const { data, error } = await this.client.auth.signInWithPassword({
        phone: options.phone,
        password: options.password,
      });

      if (error) {
        return {
          user: null,
          session: null,
          error: {
            code: error.code ?? 'SIGNIN_ERROR',
            message: error.message,
            status: error.status ?? 401,
          },
        };
      }

      return {
        user: data.user ? mapUser(data.user) : null,
        session: data.session ? mapSession(data.session) : null,
      };
    }

    throw new AuthModuleError('INVALID_SIGNIN_OPTIONS', 'Must provide email/password or phone/password', 400);
  }

  async signOut(): Promise<void> {
    const { error } = await this.client.auth.signOut();
    if (error) {
      throw new AuthModuleError('SIGNOUT_ERROR', error.message, error.status ?? 500);
    }
  }

  // ─────────────────────────────────────────────────────────────────
  // Session management
  // ─────────────────────────────────────────────────────────────────

  async getSession(): Promise<Session | null> {
    const { data, error } = await this.client.auth.getSession();
    if (error) {
      throw new AuthModuleError('SESSION_ERROR', error.message, error.status ?? 500);
    }
    return data.session ? mapSession(data.session) : null;
  }

  async refreshSession(): Promise<Session | null> {
    const { data, error } = await this.client.auth.refreshSession();
    if (error) {
      throw new AuthModuleError('REFRESH_ERROR', error.message, error.status ?? 500);
    }
    return data.session ? mapSession(data.session) : null;
  }

  async getUser(): Promise<User | null> {
    const { data, error } = await this.client.auth.getUser();
    if (error) {
      // No session is not an error, just return null
      if (error.message.includes('not authenticated')) {
        return null;
      }
      throw new AuthModuleError('USER_ERROR', error.message, error.status ?? 500);
    }
    return data.user ? mapUser(data.user) : null;
  }

  // ─────────────────────────────────────────────────────────────────
  // OAuth
  // ─────────────────────────────────────────────────────────────────

  async signInWithOAuth(
    provider: OAuthProvider,
    options?: { redirectTo?: string; scopes?: string }
  ): Promise<{ url: string }> {
    // Cast to any to handle provider type differences between our types and Supabase's
    const { data, error } = await this.client.auth.signInWithOAuth({
      provider: provider as Parameters<typeof this.client.auth.signInWithOAuth>[0]['provider'],
      options: {
        redirectTo: options?.redirectTo,
        scopes: options?.scopes,
      },
    });

    if (error) {
      throw new AuthModuleError('OAUTH_ERROR', error.message, error.status ?? 500);
    }

    return { url: data.url };
  }

  async handleOAuthCallback(params: URLSearchParams): Promise<AuthResult> {
    const code = params.get('code');
    if (!code) {
      return {
        user: null,
        session: null,
        error: {
          code: 'MISSING_CODE',
          message: 'OAuth callback missing code parameter',
          status: 400,
        },
      };
    }

    const { data, error } = await this.client.auth.exchangeCodeForSession(code);

    if (error) {
      return {
        user: null,
        session: null,
        error: {
          code: error.code ?? 'OAUTH_CALLBACK_ERROR',
          message: error.message,
          status: error.status ?? 400,
        },
      };
    }

    return {
      user: data.user ? mapUser(data.user) : null,
      session: data.session ? mapSession(data.session) : null,
    };
  }

  // ─────────────────────────────────────────────────────────────────
  // Password management
  // ─────────────────────────────────────────────────────────────────

  async resetPassword(email: string, redirectTo?: string): Promise<void> {
    const { error } = await this.client.auth.resetPasswordForEmail(email, {
      redirectTo,
    });
    if (error) {
      throw new AuthModuleError('PASSWORD_RESET_ERROR', error.message, error.status ?? 500);
    }
  }

  async updatePassword(newPassword: string): Promise<void> {
    const { error } = await this.client.auth.updateUser({ password: newPassword });
    if (error) {
      throw new AuthModuleError('PASSWORD_UPDATE_ERROR', error.message, error.status ?? 500);
    }
  }

  // ─────────────────────────────────────────────────────────────────
  // MFA
  // ─────────────────────────────────────────────────────────────────

  async enrollMFA(method: MFAMethod): Promise<MFAEnrollment> {
    if (method !== 'totp') {
      throw new AuthModuleError('UNSUPPORTED_MFA', `Supabase only supports TOTP MFA, not ${method}`, 400);
    }

    const { data, error } = await this.client.auth.mfa.enroll({
      factorType: 'totp',
    });

    if (error) {
      throw new AuthModuleError('MFA_ENROLL_ERROR', error.message, 500);
    }

    return {
      id: data.id,
      type: 'totp',
      totpSecret: data.totp.secret,
      totpUri: data.totp.uri,
    };
  }

  async verifyMFA(factorId: string, code: string): Promise<AuthResult> {
    const { data, error } = await this.client.auth.mfa.challengeAndVerify({
      factorId,
      code,
    });

    if (error) {
      return {
        user: null,
        session: null,
        error: {
          code: 'MFA_VERIFY_ERROR',
          message: error.message,
          status: 401,
        },
      };
    }

    // After MFA verification, get the current session
    const sessionResult = await this.getSession();
    const userResult = await this.getUser();

    return {
      user: userResult,
      session: sessionResult,
    };
  }

  async unenrollMFA(factorId: string): Promise<void> {
    const { error } = await this.client.auth.mfa.unenroll({ factorId });
    if (error) {
      throw new AuthModuleError('MFA_UNENROLL_ERROR', error.message, 500);
    }
  }

  async listMFAFactors(): Promise<MFAEnrollment[]> {
    const { data, error } = await this.client.auth.mfa.listFactors();
    if (error) {
      throw new AuthModuleError('MFA_LIST_ERROR', error.message, 500);
    }

    return data.totp.map((factor) => ({
      id: factor.id,
      type: 'totp' as const,
    }));
  }

  // ─────────────────────────────────────────────────────────────────
  // User management
  // ─────────────────────────────────────────────────────────────────

  async updateUser(updates: Partial<Pick<User, 'email' | 'phone' | 'metadata'>>): Promise<User> {
    const { data, error } = await this.client.auth.updateUser({
      email: updates.email,
      phone: updates.phone,
      data: updates.metadata,
    });

    if (error) {
      throw new AuthModuleError('USER_UPDATE_ERROR', error.message, error.status ?? 500);
    }

    return mapUser(data.user);
  }

  async deleteUser(): Promise<void> {
    // Supabase doesn't have a direct deleteUser method on client-side
    // This requires the admin API
    if (!this.adminClient) {
      throw new AuthModuleError('ADMIN_REQUIRED', 'Deleting user requires admin privileges', 403);
    }

    const user = await this.getUser();
    if (!user) {
      throw new AuthModuleError('NOT_AUTHENTICATED', 'No authenticated user', 401);
    }

    const { error } = await this.adminClient.auth.admin.deleteUser(user.id);
    if (error) {
      throw new AuthModuleError('USER_DELETE_ERROR', error.message, 500);
    }
  }

  // ─────────────────────────────────────────────────────────────────
  // Real-time subscriptions
  // ─────────────────────────────────────────────────────────────────

  onAuthStateChange(callback: AuthStateChangeCallback): () => void {
    const { data } = this.client.auth.onAuthStateChange((event, session) => {
      const mappedEvent = mapAuthEvent(event);
      if (mappedEvent) {
        callback(mappedEvent, session ? mapSession(session) : null);
      }
    });

    return () => {
      data.subscription.unsubscribe();
    };
  }

  // ─────────────────────────────────────────────────────────────────
  // Admin API
  // ─────────────────────────────────────────────────────────────────

  admin = this.adminClient
    ? {
        listUsers: async (options?: { page?: number; perPage?: number }) => {
          const page = options?.page ?? 1;
          const perPage = options?.perPage ?? 50;

          const { data, error } = await this.adminClient!.auth.admin.listUsers({
            page,
            perPage,
          });

          if (error) {
            throw new AuthModuleError('ADMIN_LIST_ERROR', error.message, 500);
          }

          return {
            users: data.users.map(mapUser),
            total: data.users.length, // Supabase doesn't return total in listUsers
          };
        },

        getUserById: async (id: string): Promise<User | null> => {
          const { data, error } = await this.adminClient!.auth.admin.getUserById(id);
          if (error) {
            if (error.message.includes('not found')) {
              return null;
            }
            throw new AuthModuleError('ADMIN_GET_ERROR', error.message, 500);
          }
          return data.user ? mapUser(data.user) : null;
        },

        deleteUser: async (id: string): Promise<void> => {
          const { error } = await this.adminClient!.auth.admin.deleteUser(id);
          if (error) {
            throw new AuthModuleError('ADMIN_DELETE_ERROR', error.message, 500);
          }
        },

        updateUser: async (
          id: string,
          updates: Partial<Pick<User, 'email' | 'phone' | 'metadata' | 'appMetadata'>>
        ): Promise<User> => {
          const { data, error } = await this.adminClient!.auth.admin.updateUserById(id, {
            email: updates.email,
            phone: updates.phone,
            user_metadata: updates.metadata,
            app_metadata: updates.appMetadata,
          });

          if (error) {
            throw new AuthModuleError('ADMIN_UPDATE_ERROR', error.message, 500);
          }

          return mapUser(data.user);
        },
      }
    : undefined;
}
