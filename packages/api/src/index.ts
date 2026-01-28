import { Hono } from 'hono';
import { cors } from 'hono/cors';
import type { AuthAdapter, SupabaseAuthConfig } from '@for-the-people/auth-core';
import { AuthService, SupabaseAuthAdapter, InMemoryAuthAdapter } from '@for-the-people/auth-core';
import { sessionMiddleware } from './middleware/session.js';
import { authRoutes } from './routes/auth.js';
import { oauthRoutes } from './routes/oauth.js';

export interface AppConfig {
  /** Pre-configured auth adapter */
  adapter?: AuthAdapter;
  /** Supabase config (if not providing adapter) */
  supabase?: SupabaseAuthConfig;
  /** Use in-memory adapter for testing */
  useMemory?: boolean;
  /** CORS origins */
  corsOrigins?: string[];
}

/**
 * Create the auth API Hono app
 */
export function createApp(config: AppConfig): Hono {
  const app = new Hono();

  // Determine which adapter to use
  let adapter: AuthAdapter;
  if (config.adapter) {
    adapter = config.adapter;
  } else if (config.supabase) {
    adapter = new SupabaseAuthAdapter(config.supabase);
  } else if (config.useMemory) {
    adapter = new InMemoryAuthAdapter();
  } else {
    throw new Error('Must provide adapter, supabase config, or useMemory: true');
  }

  const authService = new AuthService(adapter);

  // CORS middleware
  app.use(
    '*',
    cors({
      origin: config.corsOrigins ?? ['*'],
      allowMethods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
      allowHeaders: ['Content-Type', 'Authorization'],
      exposeHeaders: ['Content-Length'],
      credentials: true,
    })
  );

  // Session middleware for all /api routes
  app.use('/api/*', sessionMiddleware(authService));

  // Health check
  app.get('/health', (c) =>
    c.json({
      status: 'ok',
      provider: authService.provider,
      timestamp: new Date().toISOString(),
    })
  );

  // Mount routes
  app.route('/api/v1/auth', authRoutes(authService));
  app.route('/api/v1/auth/oauth', oauthRoutes(authService));

  return app;
}

// Re-export for convenience
export { sessionMiddleware, requireAuth, optionalAuth } from './middleware/session.js';
export { authRoutes } from './routes/auth.js';
export { oauthRoutes } from './routes/oauth.js';
