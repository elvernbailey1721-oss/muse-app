import crypto from 'node:crypto';

export function newId(): string {
  return crypto.randomUUID();
}

export function sha256Hex(input: string): string {
  return crypto.createHash('sha256').update(input, 'utf8').digest('hex');
}

export function randomToken(bytes = 32): string {
  return crypto.randomBytes(bytes).toString('base64url');
}

const GCM_IV_LEN = 12;

/** AES-256-GCM encrypt for secrets at rest. Returns base64(iv || authTag || ciphertext). */
export function encryptSecret(key: Buffer, plaintext: string): string {
  if (key.length !== 32) throw new Error('encryption key must be 32 bytes');
  const iv = crypto.randomBytes(GCM_IV_LEN);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const ct = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([iv, tag, ct]).toString('base64');
}

export function decryptSecret(key: Buffer, payload: string): string {
  if (key.length !== 32) throw new Error('encryption key must be 32 bytes');
  const buf = Buffer.from(payload, 'base64');
  const iv = buf.subarray(0, GCM_IV_LEN);
  const tag = buf.subarray(GCM_IV_LEN, GCM_IV_LEN + 16);
  const ct = buf.subarray(GCM_IV_LEN + 16);
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ct), decipher.final()]).toString('utf8');
}

/** Constant-time string compare for secrets (e.g. state hashes). */
export function safeEqual(a: string, b: string): boolean {
  const ab = Buffer.from(a, 'utf8');
  const bb = Buffer.from(b, 'utf8');
  if (ab.length !== bb.length) return false;
  return crypto.timingSafeEqual(ab, bb);
}
