// Types
export type {
  OAuthProvider,
  MFAMethod,
  SessionType,
  AuthCapabilities,
  User,
  Session,
  SignUpOptions,
  SignInOptions,
  AuthResult,
  AuthError,
  MFAEnrollment,
  AuthStateEvent,
  AuthStateChangeCallback,
  SupabaseAuthConfig,
} from './types/index.js';

export { AuthModuleError } from './types/index.js';

// Adapter interface
export type { AuthAdapter } from './adapters/adapter.js';

// Supabase adapter
export { SupabaseAuthAdapter } from './adapters/supabase.js';

// In-memory adapter (for testing)
export { InMemoryAuthAdapter } from './adapters/memory.js';

// Service
export { AuthService } from './services/auth.js';
