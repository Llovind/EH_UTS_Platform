import crypto from 'node:crypto';

const SCRYPT_N = 16384;
const SCRYPT_R = 8;
const SCRYPT_P = 1;
const KEY_BYTES = 32;

export function normalizeId(value) {
  return String(value ?? '').trim().toUpperCase();
}

export function isStrongPassword(value) {
  const password = String(value ?? '');
  return password.length >= 12 && password.length <= 200;
}

export function hashPassword(password) {
  const salt = crypto.randomBytes(16);
  const derived = crypto.scryptSync(String(password), salt, KEY_BYTES, {
    N: SCRYPT_N,
    r: SCRYPT_R,
    p: SCRYPT_P,
    maxmem: 32 * 1024 * 1024,
  });
  return `scrypt$${SCRYPT_N}$${SCRYPT_R}$${SCRYPT_P}$${salt.toString('base64url')}$${derived.toString('base64url')}`;
}

export function verifyPassword(password, encoded) {
  try {
    const [scheme, n, r, p, saltText, hashText] = String(encoded).split('$');
    if (scheme !== 'scrypt') return false;
    const salt = Buffer.from(saltText, 'base64url');
    const expected = Buffer.from(hashText, 'base64url');
    const actual = crypto.scryptSync(String(password), salt, expected.length, {
      N: Number(n), r: Number(r), p: Number(p), maxmem: 32 * 1024 * 1024,
    });
    return expected.length === actual.length && crypto.timingSafeEqual(expected, actual);
  } catch {
    return false;
  }
}

export function randomToken(bytes = 32) {
  return crypto.randomBytes(bytes).toString('base64url');
}

export function sha256(value) {
  return crypto.createHash('sha256').update(String(value)).digest('hex');
}

function keyFromBase64(value) {
  const key = Buffer.from(String(value || ''), 'base64');
  if (key.length !== 32) throw new Error('APP_KEY_BASE64 must decode to 32 bytes');
  return key;
}

export function encryptSecret(plaintext, appKeyBase64) {
  const key = keyFromBase64(appKeyBase64);
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const ciphertext = Buffer.concat([cipher.update(String(plaintext), 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return [iv, tag, ciphertext].map((part) => part.toString('base64url')).join('.');
}

export function decryptSecret(encoded, appKeyBase64) {
  const key = keyFromBase64(appKeyBase64);
  const [ivText, tagText, ciphertextText] = String(encoded).split('.');
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, Buffer.from(ivText, 'base64url'));
  decipher.setAuthTag(Buffer.from(tagText, 'base64url'));
  return Buffer.concat([decipher.update(Buffer.from(ciphertextText, 'base64url')), decipher.final()]).toString('utf8');
}

function base32ToBuffer(value) {
  const clean = String(value || '').toUpperCase().replace(/[^A-Z2-7]/g, '');
  let bits = '';
  for (const char of clean) bits += ("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567".indexOf(char)).toString(2).padStart(5, '0');
  const bytes = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) bytes.push(parseInt(bits.slice(i, i + 8), 2));
  return Buffer.from(bytes);
}

export function verifyTotp(code, secret, now = Date.now()) {
  if (!secret) return process.env.NODE_ENV !== 'production';
  const normalized = String(code || '').replace(/\s/g, '');
  if (!/^\d{6}$/.test(normalized)) return false;
  const key = base32ToBuffer(secret);
  if (!key.length) return false;
  const counter = Math.floor(now / 1000 / 30);
  for (let offset = -1; offset <= 1; offset += 1) {
    const data = Buffer.alloc(8);
    data.writeBigUInt64BE(BigInt(counter + offset));
    const digest = crypto.createHmac('sha1', key).update(data).digest();
    const index = digest[digest.length - 1] & 0x0f;
    const number = ((digest[index] & 0x7f) << 24) | (digest[index + 1] << 16) | (digest[index + 2] << 8) | digest[index + 3];
    const expected = String(number % 1_000_000).padStart(6, '0');
    if (crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(normalized))) return true;
  }
  return false;
}

export function isInCidr(ip, cidr) {
  const [networkText, prefixText] = String(cidr).split('/');
  const prefix = Number(prefixText);
  const parts = String(ip || '').replace(/^::ffff:/, '').split('.').map(Number);
  const network = networkText.split('.').map(Number);
  if (parts.length !== 4 || network.length !== 4 || !Number.isInteger(prefix) || prefix < 0 || prefix > 32 || parts.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) return false;
  const ipNumber = parts.reduce((n, octet) => (n * 256) + octet, 0) >>> 0;
  const networkNumber = network.reduce((n, octet) => (n * 256) + octet, 0) >>> 0;
  const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
  return (ipNumber & mask) === (networkNumber & mask);
}

export function ipv4ToNumber(value) {
  const parts = String(value || '').trim().split('.').map(Number);
  if (parts.length !== 4 || parts.some((part) => !Number.isInteger(part) || part < 0 || part > 255)) return null;
  return parts.reduce((number, part) => ((number * 256) + part) >>> 0, 0);
}

export function numberToIpv4(value) {
  const number = Number(value);
  if (!Number.isInteger(number) || number < 0 || number > 0xffffffff) throw new Error('Invalid IPv4 number');
  return [24, 16, 8, 0].map((shift) => (number >>> shift) & 255).join('.');
}

export function ipv4InRange(ip, startIp, endIp) {
  const value = ipv4ToNumber(ip);
  const start = ipv4ToNumber(startIp);
  const end = ipv4ToNumber(endIp);
  return value !== null && start !== null && end !== null && value >= start && value <= end;
}

export function validWireguardPublicKey(value) {
  return /^[A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]=$/.test(String(value || '').trim());
}

export function validTargetIp(ip, cidr = '10.77.4.0/24', startIp = '10.77.4.100', endIp = '10.77.4.129') {
  const text = String(ip || '').trim();
  return isInCidr(text, cidr) && ipv4InRange(text, startIp, endIp);
}

export function validFlag(flag) {
  return /^MBC\{[A-Za-z0-9_!@#$%\-]{4,100}\}$/.test(String(flag || ''));
}
