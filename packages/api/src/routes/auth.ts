import { Hono } from 'hono';
import type { ContentfulStatusCode } from 'hono/utils/http-status';
import type { AuthService, SignUpOptions, SignInOptions, AuthError } from '@for-the-people/auth-core';
import { requireAuth } from '../middleware/session.js';

/** Helper to return error response with proper typing */
function errorResponse(c: { json: (data: unknown, status: ContentfulStatusCode) => Response }, error: AuthError) {
  // Default to 500 if status is not a valid contentful status
  const status = (error.status >= 200 && error.status < 600 ? error.status : 500) as ContentfulStatusCode;
  return c.json({ error }, status);
}

export function authRoutes(authService: AuthService): Hono {
  const app = new Hono();

  // POST /signup — sign up with email/password
  app.post('/signup', async (c) => {
    try {
      const body = await c.req.json();
      const { email, password, phone, metadata, redirectTo } = body as SignUpOptions;

      if (!email || !password) {
        return c.json(
          { error: { code: 'MISSING_FIELDS', message: 'Email and password are required', status: 400 } },
          400
        );
      }

      const result = await authService.signUp({ email, password, phone, metadata, redirectTo });

      if (result.error) {
        return errorResponse(c, result.error);
      }

      return c.json({ user: result.user, session: result.session }, 201);
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Unknown error';
      return c.json({ error: { code: 'SIGNUP_ERROR', message, status: 500 } }, 500);
    }
  });

  // POST /signin — sign in
  app.post('/signin', async (c) => {
    try {
      const body = await c.req.json();
      const { email, phone, password, provider, redirectTo } = body as SignInOptions;

      const result = await authService.signIn({ email, phone, password, provider, redirectTo });

      if (result.error) {
        return errorResponse(c, result.error);
      }

      return c.json({ user: result.user, session: result.session });
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Unknown error';
      return c.json({ error: { code: 'SIGNIN_ERROR', message, status: 500 } }, 500);
    }
  });

  // POST /signout — sign out
  app.post('/signout', async (c) => {
    try {
      await authService.signOut();
      return c.json({ success: true });
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Unknown error';
      return c.json({ error: { code: 'SIGNOUT_ERROR', message, status: 500 } }, 500);
    }
  });

  // GET /session — get current session
  app.get('/session', async (c) => {
    try {
      const session = await authService.getSession();
      return c.json({ session });
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Unknown error';
      return c.json({ error: { code: 'SESSION_ERROR', message, status: 500 } }, 500);
    }
  });

  // POST /refresh — refresh session
  app.post('/refresh', async (c) => {
    try {
      const session = await authService.refreshSession();
      return c.json({ session });
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Unknown error';
      return c.json({ error: { code: 'REFRESH_ERROR', message, status: 500 } }, 500);
    }
  });

  // GET /user — get current user
  app.get('/user', async (c) => {
    try {
      const user = await authService.getUser();
      if (!user) {
        return c.json({ error: { code: 'NOT_AUTHENTICATED', message: 'Not authenticated', status: 401 } }, 401);
      }
      return c.json({ user });
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Unknown error';
      return c.json({ error: { code: 'USER_ERROR', message, status: 500 } }, 500);
    }
  });

  // POST /password/reset — request password reset
  app.post('/password/reset', async (c) => {
    try {
      const body = await c.req.json();
      const { email, redirectTo } = body as { email: string; redirectTo?: string };

      if (!email) {
        return c.json(
          { error: { code: 'MISSING_EMAIL', message: 'Email is required', status: 400 } },
          400
        );
      }

      await authService.resetPassword(email, redirectTo);
      return c.json({ success: true, message: 'Password reset email sent' });
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Unknown error';
      return c.json({ error: { code: 'PASSWORD_RESET_ERROR', message, status: 500 } }, 500);
    }
  });

  // POST /password/update — update password (requires auth)
  app.post('/password/update', requireAuth(), async (c) => {
    try {
      const body = await c.req.json();
      const { password } = body as { password: string };

      if (!password) {
        return c.json(
          { error: { code: 'MISSING_PASSWORD', message: 'New password is required', status: 400 } },
          400
        );
      }

      await authService.updatePassword(password);
      return c.json({ success: true, message: 'Password updated' });
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Unknown error';
      return c.json({ error: { code: 'PASSWORD_UPDATE_ERROR', message, status: 500 } }, 500);
    }
  });

  // GET /capabilities — get adapter capabilities
  app.get('/capabilities', (c) => {
    const capabilities = authService.getCapabilities();
    return c.json({ capabilities });
  });

  // POST /mfa/enroll — enroll MFA (if supported)
  app.post('/mfa/enroll', requireAuth(), async (c) => {
    try {
      const body = await c.req.json();
      const { method } = body as { method: 'totp' | 'sms' | 'email' };

      if (!method) {
        return c.json(
          { error: { code: 'MISSING_METHOD', message: 'MFA method is required', status: 400 } },
          400
        );
      }

      const enrollment = await authService.enrollMFA(method);
      return c.json({ enrollment });
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Unknown error';
      const rawStatus = (err as { status?: number }).status ?? 500;
      const status = (rawStatus >= 200 && rawStatus < 600 ? rawStatus : 500) as ContentfulStatusCode;
      return c.json({ error: { code: 'MFA_ENROLL_ERROR', message, status: rawStatus } }, status);
    }
  });

  // POST /mfa/verify — verify MFA code
  app.post('/mfa/verify', async (c) => {
    try {
      const body = await c.req.json();
      const { factorId, code } = body as { factorId: string; code: string };

      if (!factorId || !code) {
        return c.json(
          { error: { code: 'MISSING_FIELDS', message: 'factorId and code are required', status: 400 } },
          400
        );
      }

      const result = await authService.verifyMFA(factorId, code);

      if (result.error) {
        return errorResponse(c, result.error);
      }

      return c.json({ user: result.user, session: result.session });
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Unknown error';
      const rawStatus = (err as { status?: number }).status ?? 500;
      const status = (rawStatus >= 200 && rawStatus < 600 ? rawStatus : 500) as ContentfulStatusCode;
      return c.json({ error: { code: 'MFA_VERIFY_ERROR', message, status: rawStatus } }, status);
    }
  });

  // GET /mfa/factors — list enrolled MFA factors
  app.get('/mfa/factors', requireAuth(), async (c) => {
    try {
      const factors = await authService.listMFAFactors();
      return c.json({ factors });
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Unknown error';
      return c.json({ error: { code: 'MFA_LIST_ERROR', message, status: 500 } }, 500);
    }
  });

  // DELETE /mfa/:factorId — unenroll MFA factor
  app.delete('/mfa/:factorId', requireAuth(), async (c) => {
    try {
      const factorId = c.req.param('factorId');
      await authService.unenrollMFA(factorId);
      return c.json({ success: true });
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Unknown error';
      const rawStatus = (err as { status?: number }).status ?? 500;
      const status = (rawStatus >= 200 && rawStatus < 600 ? rawStatus : 500) as ContentfulStatusCode;
      return c.json({ error: { code: 'MFA_UNENROLL_ERROR', message, status: rawStatus } }, status);
    }
  });

  return app;
}
