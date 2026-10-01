import { Router } from 'express';
import { Identities, Memberships, Organizations, Providers, Users } from '../db/models.js';
import { authenticate, type RequestContext } from '../auth/middleware.js';

export function meRoutes(rc: RequestContext): Router {
  const r = Router();
  const { db } = rc;
  const auth = authenticate(rc);

  r.get('/me', auth, async (req, res) => {
    const user = await Users.byId(db, req.auth!.userId);
    if (!user) {
      res.status(401).json({ error: 'unauthorized', message: 'User not found' });
      return;
    }
    const memberships = await Memberships.byUser(db, user.id);
    const orgs = [];
    for (const m of memberships) {
      const org = await Organizations.byId(db, m.org_id);
      if (org) orgs.push({ id: org.id, name: org.name, slug: org.slug, role: m.role });
    }
    const identityRows = await Identities.byUser(db, user.id);
    const identities = await Promise.all(
      identityRows.map(async (i) => {
        const provider = await Providers.byId(db, i.provider_id);
        return {
          provider_id: i.provider_id,
          provider_type: provider?.type ?? 'unknown',
          email: i.email,
          email_verified: i.email_verified,
          linked_at: i.linked_at,
        };
      }),
    );
    res.json({
      id: user.id,
      email: user.email,
      name: user.name,
      avatar_url: user.avatar_url,
      orgs,
      identities,
    });
  });

  r.patch('/me', auth, async (req, res) => {
    const patch: { name?: string | null; avatar_url?: string | null } = {};
    if ('name' in req.body) {
      const name = req.body.name;
      if (name !== null && (typeof name !== 'string' || name.length > 200)) {
        res.status(400).json({ error: 'bad_request', message: 'Invalid name' });
        return;
      }
      patch.name = name;
    }
    if ('avatar_url' in req.body) {
      const avatar = req.body.avatar_url;
      if (avatar !== null && (typeof avatar !== 'string' || avatar.length > 2048 || !/^https?:\/\//.test(avatar))) {
        res.status(400).json({ error: 'bad_request', message: 'Invalid avatar_url' });
        return;
      }
      patch.avatar_url = avatar;
    }
    // Email is identity-managed (SSO) and cannot be changed here.
    if (Object.keys(patch).length === 0) {
      res.status(400).json({ error: 'bad_request', message: 'Nothing to update' });
      return;
    }
    await Users.update(db, req.auth!.userId, patch);
    const user = await Users.byId(db, req.auth!.userId);
    res.json({ id: user!.id, email: user!.email, name: user!.name, avatar_url: user!.avatar_url });
  });

  return r;
}
