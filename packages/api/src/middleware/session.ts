import type { Context, Next } from 'hono';
import type { AuthService, Session } from '@for-the-people/auth-core';

declare module 'hono' {
  interface ContextVariableMap {
    session: Session | null;
    authService: AuthService;
  }
}

/**
 * Session middleware that validates JWT and attaches session to context
 */
export function sessionMiddleware(authService: AuthService) {
  return async (c: Context, next: Next) => {
    // Store authService in context for routes to use
    c.set('authService', authService);

    // Try to get session from Authorization header
    const authHeader = c.req.header('Authorization');
    let session: Session | null = null;

    if (authHeader?.startsWith('Bearer ')) {
      try {
        // The auth service handles token validation internally
        session = await authService.getSession();

        // Verify token hasn't expired
        if (session && session.expiresAt <= Math.floor(Date.now() / 1000)) {
          session = null;
        }
      } catch {
        // Invalid token, session stays null
        session = null;
      }
    }

    c.set('session', session);
    await next();
  };
}

/**
 * Require authentication middleware
 * Returns 401 if no valid session
 */
export function requireAuth() {
  return async (c: Context, next: Next) => {
    const session = c.get('session');

    if (!session) {
      return c.json(
        {
          error: {
            code: 'UNAUTHORIZED',
            message: 'Authentication required',
            status: 401,
          },
        },
        401
      );
    }

    await next();
  };
}

/**
 * Optional auth middleware - continues even without session
 */
export function optionalAuth() {
  return async (_c: Context, next: Next) => {
    // Session is already set by sessionMiddleware
    await next();
  };
}
