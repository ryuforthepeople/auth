import type { AuthAdapter } from './adapter.js';
import type {
  AuthCapabilities,
  OAuthProvider,
  User,
  Session,
  SignUpOptions,
  SignInOptions,
  AuthResult,
  AuthStateChangeCallback,
  AuthStateEvent,
} from '../types/index.js';
import { AuthModuleError } from '../types/index.js';

interface StoredUser extends User {
  password: string;
}

/**
 * In-Memory Auth Adapter
 * For testing and development without external services
 */
export class InMemoryAuthAdapter implements AuthAdapter {
  readonly provider = 'memory';

  private users = new Map<string, StoredUser>();
  private sessions = new Map<string, Session>();
  private currentSessionId: string | null = null;
  private listeners: AuthStateChangeCallback[] = [];
  private idCounter = 0;

  constructor(options?: { initialUsers?: Array<SignUpOptions & { id?: string }> }) {
    // Pre-populate with initial users if provided
    if (options?.initialUsers) {
      for (const userData of options.initialUsers) {
        const id = userData.id ?? this.generateId();
        const now = new Date().toISOString();
        this.users.set(id, {
          id,
          email: userData.email,
          phone: userData.phone,
          emailVerified: true,
          phoneVerified: !!userData.phone,
          createdAt: now,
          updatedAt: now,
          metadata: userData.metadata,
          password: userData.password,
        });
      }
    }
  }

  private generateId(): string {
    return `user_${++this.idCounter}_${Date.now()}`;
  }

  private generateToken(): string {
    return `token_${Math.random().toString(36).substring(2)}_${Date.now()}`;
  }

  private notify(event: AuthStateEvent, session: Session | null): void {
    for (const listener of this.listeners) {
      listener(event, session);
    }
  }

  getCapabilities(): AuthCapabilities {
    return {
      provider: 'memory',
      version: '1.0.0',
      oauth: {
        supported: false,
        providers: [],
      },
      mfa: {
        supported: false,
        methods: [],
        required: false,
      },
      sessions: {
        type: 'jwt',
        refreshSupported: true,
        maxAgeSeconds: 3600,
      },
      features: {
        passwordless: false,
        magicLink: false,
        phoneAuth: false,
        emailVerification: false,
        passwordReset: true,
        userMetadata: true,
        adminAPI: true,
      },
    };
  }

  // ─────────────────────────────────────────────────────────────────
  // Core authentication
  // ─────────────────────────────────────────────────────────────────

  async signUp(options: SignUpOptions): Promise<AuthResult> {
    // Check if email already exists
    for (const user of this.users.values()) {
      if (user.email === options.email) {
        return {
          user: null,
          session: null,
          error: {
            code: 'EMAIL_EXISTS',
            message: 'A user with this email already exists',
            status: 409,
          },
        };
      }
    }

    const id = this.generateId();
    const now = new Date().toISOString();
    const user: StoredUser = {
      id,
      email: options.email,
      phone: options.phone,
      emailVerified: false,
      phoneVerified: false,
      createdAt: now,
      updatedAt: now,
      metadata: options.metadata,
      password: options.password,
    };

    this.users.set(id, user);

    // Create session
    const accessToken = this.generateToken();
    const session: Session = {
      accessToken,
      refreshToken: this.generateToken(),
      expiresAt: Math.floor(Date.now() / 1000) + 3600,
      user: this.sanitizeUser(user),
    };

    this.sessions.set(accessToken, session);
    this.currentSessionId = accessToken;

    this.notify('SIGNED_IN', session);

    return {
      user: this.sanitizeUser(user),
      session,
    };
  }

  async signIn(options: SignInOptions): Promise<AuthResult> {
    if (!options.email || !options.password) {
      return {
        user: null,
        session: null,
        error: {
          code: 'INVALID_CREDENTIALS',
          message: 'Email and password are required',
          status: 400,
        },
      };
    }

    // Find user by email
    let foundUser: StoredUser | undefined;
    for (const user of this.users.values()) {
      if (user.email === options.email) {
        foundUser = user;
        break;
      }
    }

    if (!foundUser || foundUser.password !== options.password) {
      return {
        user: null,
        session: null,
        error: {
          code: 'INVALID_CREDENTIALS',
          message: 'Invalid email or password',
          status: 401,
        },
      };
    }

    // Update last sign in
    foundUser.lastSignInAt = new Date().toISOString();
    foundUser.updatedAt = new Date().toISOString();

    // Create session
    const accessToken = this.generateToken();
    const session: Session = {
      accessToken,
      refreshToken: this.generateToken(),
      expiresAt: Math.floor(Date.now() / 1000) + 3600,
      user: this.sanitizeUser(foundUser),
    };

    this.sessions.set(accessToken, session);
    this.currentSessionId = accessToken;

    this.notify('SIGNED_IN', session);

    return {
      user: this.sanitizeUser(foundUser),
      session,
    };
  }

  async signOut(): Promise<void> {
    if (this.currentSessionId) {
      this.sessions.delete(this.currentSessionId);
      this.currentSessionId = null;
    }
    this.notify('SIGNED_OUT', null);
  }

  // ─────────────────────────────────────────────────────────────────
  // Session management
  // ─────────────────────────────────────────────────────────────────

  async getSession(): Promise<Session | null> {
    if (!this.currentSessionId) return null;
    return this.sessions.get(this.currentSessionId) ?? null;
  }

  async refreshSession(): Promise<Session | null> {
    const currentSession = await this.getSession();
    if (!currentSession) return null;

    // Create new session
    const accessToken = this.generateToken();
    const newSession: Session = {
      accessToken,
      refreshToken: this.generateToken(),
      expiresAt: Math.floor(Date.now() / 1000) + 3600,
      user: currentSession.user,
    };

    // Remove old, add new
    this.sessions.delete(this.currentSessionId!);
    this.sessions.set(accessToken, newSession);
    this.currentSessionId = accessToken;

    this.notify('TOKEN_REFRESHED', newSession);

    return newSession;
  }

  async getUser(): Promise<User | null> {
    const session = await this.getSession();
    return session?.user ?? null;
  }

  // ─────────────────────────────────────────────────────────────────
  // OAuth (not supported in memory adapter)
  // ─────────────────────────────────────────────────────────────────

  async signInWithOAuth(_provider: OAuthProvider): Promise<{ url: string }> {
    throw new AuthModuleError(
      'OAUTH_NOT_SUPPORTED',
      'OAuth is not supported by the in-memory adapter',
      501
    );
  }

  async handleOAuthCallback(_params: URLSearchParams): Promise<AuthResult> {
    return {
      user: null,
      session: null,
      error: {
        code: 'OAUTH_NOT_SUPPORTED',
        message: 'OAuth is not supported by the in-memory adapter',
        status: 501,
      },
    };
  }

  // ─────────────────────────────────────────────────────────────────
  // Password management
  // ─────────────────────────────────────────────────────────────────

  async resetPassword(_email: string, _redirectTo?: string): Promise<void> {
    // In memory adapter, this is a no-op
    // In real implementation, this would send an email
  }

  async updatePassword(newPassword: string): Promise<void> {
    const user = await this.getUser();
    if (!user) {
      throw new AuthModuleError('NOT_AUTHENTICATED', 'Must be signed in to update password', 401);
    }

    const storedUser = this.users.get(user.id);
    if (!storedUser) {
      throw new AuthModuleError('USER_NOT_FOUND', 'User not found', 404);
    }

    storedUser.password = newPassword;
    storedUser.updatedAt = new Date().toISOString();
  }

  // ─────────────────────────────────────────────────────────────────
  // User management
  // ─────────────────────────────────────────────────────────────────

  async updateUser(updates: Partial<Pick<User, 'email' | 'phone' | 'metadata'>>): Promise<User> {
    const currentUser = await this.getUser();
    if (!currentUser) {
      throw new AuthModuleError('NOT_AUTHENTICATED', 'Must be signed in to update user', 401);
    }

    const storedUser = this.users.get(currentUser.id);
    if (!storedUser) {
      throw new AuthModuleError('USER_NOT_FOUND', 'User not found', 404);
    }

    if (updates.email) storedUser.email = updates.email;
    if (updates.phone) storedUser.phone = updates.phone;
    if (updates.metadata) storedUser.metadata = { ...storedUser.metadata, ...updates.metadata };
    storedUser.updatedAt = new Date().toISOString();

    // Update session user
    if (this.currentSessionId) {
      const session = this.sessions.get(this.currentSessionId);
      if (session) {
        session.user = this.sanitizeUser(storedUser);
      }
    }

    this.notify('USER_UPDATED', await this.getSession());

    return this.sanitizeUser(storedUser);
  }

  async deleteUser(): Promise<void> {
    const user = await this.getUser();
    if (!user) {
      throw new AuthModuleError('NOT_AUTHENTICATED', 'Must be signed in to delete account', 401);
    }

    this.users.delete(user.id);
    await this.signOut();
  }

  // ─────────────────────────────────────────────────────────────────
  // Real-time subscriptions
  // ─────────────────────────────────────────────────────────────────

  onAuthStateChange(callback: AuthStateChangeCallback): () => void {
    this.listeners.push(callback);
    return () => {
      const index = this.listeners.indexOf(callback);
      if (index > -1) {
        this.listeners.splice(index, 1);
      }
    };
  }

  // ─────────────────────────────────────────────────────────────────
  // Admin API
  // ─────────────────────────────────────────────────────────────────

  admin = {
    listUsers: async (options?: { page?: number; perPage?: number }) => {
      const page = options?.page ?? 1;
      const perPage = options?.perPage ?? 50;
      const allUsers = Array.from(this.users.values()).map((u) => this.sanitizeUser(u));
      const start = (page - 1) * perPage;
      const users = allUsers.slice(start, start + perPage);

      return {
        users,
        total: allUsers.length,
      };
    },

    getUserById: async (id: string): Promise<User | null> => {
      const user = this.users.get(id);
      return user ? this.sanitizeUser(user) : null;
    },

    deleteUser: async (id: string): Promise<void> => {
      if (!this.users.has(id)) {
        throw new AuthModuleError('USER_NOT_FOUND', 'User not found', 404);
      }
      this.users.delete(id);
    },

    updateUser: async (
      id: string,
      updates: Partial<Pick<User, 'email' | 'phone' | 'metadata' | 'appMetadata'>>
    ): Promise<User> => {
      const user = this.users.get(id);
      if (!user) {
        throw new AuthModuleError('USER_NOT_FOUND', 'User not found', 404);
      }

      if (updates.email) user.email = updates.email;
      if (updates.phone) user.phone = updates.phone;
      if (updates.metadata) user.metadata = { ...user.metadata, ...updates.metadata };
      if (updates.appMetadata) user.appMetadata = { ...user.appMetadata, ...updates.appMetadata };
      user.updatedAt = new Date().toISOString();

      return this.sanitizeUser(user);
    },
  };

  // ─────────────────────────────────────────────────────────────────
  // Helpers
  // ─────────────────────────────────────────────────────────────────

  private sanitizeUser(user: StoredUser): User {
    const { password: _, ...safeUser } = user;
    return safeUser;
  }

  /** For testing: clear all data */
  clear(): void {
    this.users.clear();
    this.sessions.clear();
    this.currentSessionId = null;
    this.listeners = [];
    this.idCounter = 0;
  }

  /** For testing: get raw user count */
  getUserCount(): number {
    return this.users.size;
  }
}
