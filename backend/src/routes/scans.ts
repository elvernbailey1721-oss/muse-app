import { Router } from 'express';
import { Scans, type ScanInput } from '../db/models.js';
import { audit } from '../services/audit.js';
import { authenticate, getClientIp, param, requireOrg, type RequestContext } from '../auth/middleware.js';

const HEX_COLOR = /^#[0-9a-fA-F]{6}$/;
const MAX_THUMBNAIL_BYTES = 2 * 1024 * 1024;

function validateScanInput(body: unknown): { ok: true; input: ScanInput } | { ok: false; message: string } {
  if (!body || typeof body !== 'object') return { ok: false, message: 'Invalid body' };
  const b = body as Record<string, unknown>;
  if (typeof b.name !== 'string' || b.name.length === 0 || b.name.length > 200) {
    return { ok: false, message: 'name is required (max 200 chars)' };
  }
  if (!Array.isArray(b.colors) || b.colors.length === 0 || b.colors.length > 64) {
    return { ok: false, message: 'colors must be a non-empty array (max 64)' };
  }
  for (const c of b.colors) {
    if (typeof c !== 'string' || !HEX_COLOR.test(c)) return { ok: false, message: `Invalid hex color: ${String(c)}` };
  }
  if (b.detected_color !== undefined && b.detected_color !== null && (typeof b.detected_color !== 'string' || !HEX_COLOR.test(b.detected_color))) {
    return { ok: false, message: 'detected_color must be a hex color' };
  }
  if (b.thumbnail !== undefined && b.thumbnail !== null) {
    if (typeof b.thumbnail !== 'string' || b.thumbnail.length > MAX_THUMBNAIL_BYTES) {
      return { ok: false, message: 'thumbnail too large (max 2MB base64)' };
    }
  }
  if (b.captured_at !== undefined && b.captured_at !== null && (typeof b.captured_at !== 'string' || Number.isNaN(Date.parse(b.captured_at)))) {
    return { ok: false, message: 'captured_at must be an ISO timestamp' };
  }
  return {
    ok: true,
    input: {
      name: b.name,
      colors: b.colors as string[],
      detected_color: (b.detected_color as string | null) ?? null,
      thumbnail: (b.thumbnail as string | null) ?? null,
      captured_at: (b.captured_at as string | null) ?? null,
    },
  };
}

function publicScan(s: {
  id: string;
  user_id: string;
  org_id: string;
  name: string;
  colors_json: string;
  detected_color: string | null;
  thumbnail: string | null;
  captured_at: string | null;
  created_at: string;
  updated_at: string;
}) {
  return {
    id: s.id,
    user_id: s.user_id,
    org_id: s.org_id,
    name: s.name,
    colors: JSON.parse(s.colors_json) as string[],
    detected_color: s.detected_color,
    thumbnail: s.thumbnail,
    captured_at: s.captured_at,
    created_at: s.created_at,
    updated_at: s.updated_at,
  };
}

export function scanRoutes(rc: RequestContext): Router {
  const r = Router();
  const { db } = rc;
  const auth = authenticate(rc);
  const org = requireOrg(rc);

  r.get('/scans', auth, org, async (req, res) => {
    const limit = Math.min(Math.max(Number(req.query.limit ?? 50) || 50, 1), 200);
    const offset = Math.max(Number(req.query.offset ?? 0) || 0, 0);
    // Tenant isolation: org_id comes from the session token, never the client.
    const scans = await Scans.listByOrg(db, req.auth!.org_id!, limit, offset);
    res.json({ scans: scans.map(publicScan) });
  });

  r.post('/scans', auth, org, async (req, res) => {
    const v = validateScanInput(req.body);
    if (!v.ok) {
      res.status(400).json({ error: 'bad_request', message: v.message });
      return;
    }
    const scan = await Scans.create(db, req.auth!.userId, req.auth!.org_id!, v.input);
    res.status(201).json(publicScan(scan));
  });

  r.get('/scans/:id', auth, org, async (req, res) => {
    const scan = await Scans.byIdInOrg(db, param(req, 'id'), req.auth!.org_id!);
    if (!scan) {
      // 404 for both missing and other-org scans (no org existence oracle).
      res.status(404).json({ error: 'not_found', message: 'Scan not found' });
      return;
    }
    res.json(publicScan(scan));
  });

  r.delete('/scans/:id', auth, org, async (req, res) => {
    const scan = await Scans.byIdInOrg(db, param(req, 'id'), req.auth!.org_id!);
    if (!scan) {
      res.status(404).json({ error: 'not_found', message: 'Scan not found' });
      return;
    }
    // Members may delete their own scans; admins may delete any org scan.
    const isAdmin = req.auth!.role === 'admin' || req.auth!.role === 'owner';
    if (scan.user_id !== req.auth!.userId && !isAdmin) {
      await audit(db, 'authz_denied', {
        actorUserId: req.auth!.userId,
        orgId: req.auth!.org_id,
        ip: getClientIp(req),
        userAgent: req.headers['user-agent'] ?? null,
        meta: { reason: 'not_owner', scan_id: scan.id },
      });
      res.status(403).json({ error: 'forbidden', message: 'Cannot delete another user\u2019s scan' });
      return;
    }
    await Scans.remove(db, scan.id, req.auth!.org_id!);
    res.json({ ok: true });
  });

  return r;
}
