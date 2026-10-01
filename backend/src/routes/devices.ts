import { Router } from 'express';
import { Devices } from '../db/models.js';
import { authenticate, param, type RequestContext } from '../auth/middleware.js';

const MAX_TOKEN_LEN = 4096;

export function deviceRoutes(rc: RequestContext): Router {
  const r = Router();
  const { db } = rc;
  const auth = authenticate(rc);

  r.get('/devices', auth, async (req, res) => {
    const devices = await Devices.byUser(db, req.auth!.userId);
    res.json({
      devices: devices.map((d) => ({
        id: d.id,
        platform: d.platform,
        app_version: d.app_version,
        last_seen_at: d.last_seen_at,
      })),
    });
  });

  r.post('/devices', auth, async (req, res) => {
    const { platform, token, app_version } = req.body ?? {};
    if (platform !== 'ios' && platform !== 'android') {
      res.status(400).json({ error: 'bad_request', message: 'platform must be ios|android' });
      return;
    }
    if (typeof token !== 'string' || token.length === 0 || token.length > MAX_TOKEN_LEN) {
      res.status(400).json({ error: 'bad_request', message: 'Invalid device token' });
      return;
    }
    if (app_version !== undefined && (typeof app_version !== 'string' || app_version.length > 64)) {
      res.status(400).json({ error: 'bad_request', message: 'Invalid app_version' });
      return;
    }
    const device = await Devices.upsert(db, {
      user_id: req.auth!.userId,
      platform,
      token,
      app_version: app_version ?? null,
    });
    res.status(201).json({ id: device.id, platform: device.platform });
  });

  r.delete('/devices/:id', auth, async (req, res) => {
    // Ownership check: a user can only delete their own device registrations.
    const device = await Devices.byId(db, param(req, 'id'));
    if (!device || device.user_id !== req.auth!.userId) {
      res.status(404).json({ error: 'not_found', message: 'Device not found' });
      return;
    }
    await Devices.remove(db, device.id);
    res.json({ ok: true });
  });

  return r;
}
