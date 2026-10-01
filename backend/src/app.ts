import express, { type Express } from 'express';
import type { RequestContext } from './auth/middleware.js';
import { authRoutes } from './routes/auth.js';
import { meRoutes } from './routes/me.js';
import { deviceRoutes } from './routes/devices.js';
import { scanRoutes } from './routes/scans.js';
import { adminRoutes } from './routes/admin.js';

export function createApp(rc: RequestContext): Express {
  const app = express();
  app.set('trust proxy', 1);
  app.disable('x-powered-by');

  // 5MB JSON limit accommodates optional base64 scan thumbnails.
  app.use(express.json({ limit: '5mb' }));
  // SAML ACS posts form-encoded bodies (and Apple uses form_post callbacks).
  app.use(express.urlencoded({ extended: false, limit: '5mb' }));

  app.get('/healthz', (_req, res) => res.json({ ok: true, service: 'paintscope-mobile-backend' }));

  app.use(authRoutes(rc));
  app.use(meRoutes(rc));
  app.use(deviceRoutes(rc));
  app.use(scanRoutes(rc));
  app.use(adminRoutes(rc));

  app.use((_req, res) => res.status(404).json({ error: 'not_found', message: 'Not found' }));

  // Express 5 handles async errors natively; this is the last-resort guard.
  app.use((err: unknown, _req: express.Request, res: express.Response, _next: express.NextFunction) => {
    console.error('unhandled error:', err);
    res.status(500).json({ error: 'server_error', message: 'Internal error' });
  });

  return app;
}
