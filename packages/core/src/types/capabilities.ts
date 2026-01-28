export type OAuthProvider =
  | 'google'
  | 'apple'
  | 'microsoft'
  | 'github'
  | 'facebook'
  | 'twitter'
  | 'discord'
  | 'linkedin';

export type MFAMethod = 'totp' | 'sms' | 'email';

export type SessionType = 'jwt' | 'server' | 'both';

export interface AuthCapabilities {
  /** Provider identifier */
  provider: string;
  /** Provider/adapter version */
  version: string;

  /** OAuth configuration */
  oauth: {
    supported: boolean;
    providers: OAuthProvider[];
  };

  /** Multi-factor authentication */
  mfa: {
    supported: boolean;
    methods: MFAMethod[];
    required: boolean;
  };

  /** Session management */
  sessions: {
    type: SessionType;
    refreshSupported: boolean;
    maxAgeSeconds?: number;
  };

  /** Feature flags */
  features: {
    passwordless: boolean;
    magicLink: boolean;
    phoneAuth: boolean;
    emailVerification: boolean;
    passwordReset: boolean;
    userMetadata: boolean;
    adminAPI: boolean;
  };
}
