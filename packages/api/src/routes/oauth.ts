import { Hono } from 'hono';
import type { ContentfulStatusCode } from 'hono/utils/http-status';
import type { AuthService, OAuthProvider, AuthError } from '@for-the-people/auth-core';

const VALID_PROVIDERS: OAuthProvider[] = [
  'google',
  'apple',
  'microsoft',
  'github',
  'facebook',
  'twitter',
  'discord',
  'linkedin',
];

/** Helper to return error response with proper typing */
function errorResponse(c: { json: (data: unknown, status: ContentfulStatusCode) => Response }, error: AuthError) {
  const status = (error.status >= 200 && error.status < 600 ? error.status : 500) as ContentfulStatusCode;
  return c.json({ error }, status);
}

export function oauthRoutes(authService: AuthService): Hono {
  const app = new Hono();

  // GET /oauth/:provider — initiate OAuth flow
  app.get('/:provider', async (c) => {
    try {
      const provider = c.req.param('provider') as OAuthProvider;
      const redirectTo = c.req.query('redirectTo');
      const scopes = c.req.query('scopes');

      // Validate provider
      if (!VALID_PROVIDERS.includes(provider)) {
        return c.json(
          {
            error: {
              code: 'INVALID_PROVIDER',
              message: `Invalid OAuth provider: ${provider}`,
              status: 400,
            },
          },
          400
        );
      }

      // Check if provider is supported by this adapter
      if (!authService.hasOAuthProvider(provider)) {
        return c.json(
          {
            error: {
              code: 'PROVIDER_NOT_SUPPORTED',
              message: `OAuth provider '${provider}' is not supported by this auth provider`,
              status: 400,
            },
          },
          400
        );
      }

      const { url } = await authService.signInWithOAuth(provider, {
        redirectTo,
        scopes,
      });

      // Redirect to OAuth provider
      return c.redirect(url);
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Unknown error';
      return c.json(
        { error: { code: 'OAUTH_INIT_ERROR', message, status: 500 } },
        500
      );
    }
  });

  // GET /oauth/callback — OAuth callback (handles code exchange)
  app.get('/callback', async (c) => {
    try {
      const params = new URLSearchParams(c.req.url.split('?')[1] ?? '');

      // Check for error from OAuth provider
      const error = params.get('error');
      const errorDescription = params.get('error_description');
      if (error) {
        return c.json(
          {
            error: {
              code: 'OAUTH_PROVIDER_ERROR',
              message: errorDescription ?? error,
              status: 400,
            },
          },
          400
        );
      }

      const result = await authService.handleOAuthCallback(params);

      if (result.error) {
        return errorResponse(c, result.error);
      }

      // Return session info (client can use this to store session)
      return c.json({
        user: result.user,
        session: result.session,
      });
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Unknown error';
      return c.json(
        { error: { code: 'OAUTH_CALLBACK_ERROR', message, status: 500 } },
        500
      );
    }
  });

  // GET /oauth/providers — list supported OAuth providers
  app.get('/providers', (c) => {
    const capabilities = authService.getCapabilities();

    return c.json({
      supported: capabilities.oauth.supported,
      providers: capabilities.oauth.providers,
    });
  });

  return app;
}
