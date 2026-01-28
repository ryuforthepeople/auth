# @for-the-people/auth

Provider-agnostic authentication module with capabilities-based adapter pattern.

## Packages

- **@for-the-people/auth-core** — Core types, adapters, and AuthService
- **@for-the-people/auth-api** — Hono-based REST API

## Installation

```bash
pnpm add @for-the-people/auth-core
# or with API
pnpm add @for-the-people/auth-core @for-the-people/auth-api
```

## Quick Start

### Using the Core Library

```typescript
import {
  SupabaseAuthAdapter,
  AuthService,
} from '@for-the-people/auth-core';

// Create adapter
const adapter = new SupabaseAuthAdapter({
  url: process.env.SUPABASE_URL!,
  anonKey: process.env.SUPABASE_ANON_KEY!,
  serviceRoleKey: process.env.SUPABASE_SERVICE_ROLE_KEY, // optional, for admin API
});

// Create service
const auth = new AuthService(adapter);

// Sign up
const { user, session, error } = await auth.signUp({
  email: 'user@example.com',
  password: 'securepassword123',
});

// Sign in
const result = await auth.signIn({
  email: 'user@example.com',
  password: 'securepassword123',
});

// Get current session
const session = await auth.getSession();

// Check capabilities
const caps = auth.getCapabilities();
if (caps.mfa.supported) {
  // Show MFA enrollment UI
}
if (auth.hasOAuthProvider('google')) {
  // Show Google sign-in button
}
```

### Using the API

```typescript
import { createApp } from '@for-the-people/auth-api';

const app = createApp({
  supabase: {
    url: process.env.SUPABASE_URL!,
    anonKey: process.env.SUPABASE_ANON_KEY!,
  },
  corsOrigins: ['http://localhost:3000'],
});

// Serve with your preferred runtime
export default app;
```

## Capabilities Pattern

Every adapter declares what it supports. Your app queries capabilities and adapts:

```typescript
const caps = auth.getCapabilities();

// OAuth
if (caps.oauth.supported) {
  caps.oauth.providers.forEach(provider => {
    // Render OAuth button for each supported provider
  });
}

// MFA
if (caps.mfa.supported) {
  // Show MFA settings in user profile
  caps.mfa.methods // ['totp', 'sms', 'email']
}

// Features
if (caps.features.magicLink) {
  // Show "Sign in with magic link" option
}
if (caps.features.passwordReset) {
  // Show "Forgot password?" link
}
```

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/v1/auth/signup` | Sign up with email/password |
| POST | `/api/v1/auth/signin` | Sign in |
| POST | `/api/v1/auth/signout` | Sign out |
| GET | `/api/v1/auth/session` | Get current session |
| POST | `/api/v1/auth/refresh` | Refresh session |
| GET | `/api/v1/auth/user` | Get current user |
| POST | `/api/v1/auth/password/reset` | Request password reset |
| POST | `/api/v1/auth/password/update` | Update password |
| GET | `/api/v1/auth/capabilities` | Get adapter capabilities |
| POST | `/api/v1/auth/mfa/enroll` | Enroll in MFA |
| POST | `/api/v1/auth/mfa/verify` | Verify MFA code |
| GET | `/api/v1/auth/mfa/factors` | List MFA factors |
| DELETE | `/api/v1/auth/mfa/:factorId` | Unenroll MFA |
| GET | `/api/v1/auth/oauth/:provider` | Start OAuth flow |
| GET | `/api/v1/auth/oauth/callback` | OAuth callback |
| GET | `/api/v1/auth/oauth/providers` | List OAuth providers |

## Adapters

### Supabase (default)

```typescript
import { SupabaseAuthAdapter } from '@for-the-people/auth-core';

const adapter = new SupabaseAuthAdapter({
  url: 'https://xxx.supabase.co',
  anonKey: 'eyJ...',
  serviceRoleKey: 'eyJ...', // optional
});
```

**Capabilities:**
- OAuth: google, apple, github, facebook, twitter, discord, linkedin, microsoft
- MFA: totp
- Sessions: JWT with refresh
- All features enabled

### In-Memory (testing)

```typescript
import { InMemoryAuthAdapter } from '@for-the-people/auth-core';

const adapter = new InMemoryAuthAdapter({
  initialUsers: [
    { email: 'test@example.com', password: 'password123' },
  ],
});
```

**Capabilities:**
- OAuth: not supported
- MFA: not supported
- Sessions: JWT with refresh
- Basic features only

## Building

```bash
cd auth
pnpm install
pnpm build
```

## License

MIT
