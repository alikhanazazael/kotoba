const ITERATIONS = 100000;

function b64url(buf) {
  return btoa(String.fromCharCode(...new Uint8Array(buf)))
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function b64urlDecode(str) {
  str = str.replace(/-/g, '+').replace(/_/g, '/');
  while (str.length % 4) str += '=';
  const bin = atob(str);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}

async function hashPassword(password, saltB64) {
  const enc = new TextEncoder();
  const salt = b64urlDecode(saltB64);
  const keyMaterial = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt, iterations: ITERATIONS, hash: 'SHA-256' },
    keyMaterial, 256
  );
  return b64url(bits);
}

function randomSaltB64() {
  return b64url(crypto.getRandomValues(new Uint8Array(16)).buffer);
}

async function hmac(secret, data) {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey('raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sig = await crypto.subtle.sign('HMAC', key, enc.encode(data));
  return b64url(sig);
}

async function makeToken(username, secret) {
  const payload = JSON.stringify({ u: username, exp: Date.now() + 1000 * 60 * 60 * 24 * 90 });
  const payloadB64 = b64url(new TextEncoder().encode(payload).buffer);
  const sig = await hmac(secret, payloadB64);
  return payloadB64 + '.' + sig;
}

async function verifyToken(token, secret) {
  if (!token) return null;
  const parts = token.split('.');
  if (parts.length !== 2) return null;
  const [payloadB64, sig] = parts;
  const expected = await hmac(secret, payloadB64);
  if (expected !== sig) return null;
  try {
    const payload = JSON.parse(new TextDecoder().decode(b64urlDecode(payloadB64)));
    if (!payload.u || !payload.exp || payload.exp < Date.now()) return null;
    return payload.u;
  } catch {
    return null;
  }
}

function json(data, status = 200) {
  return new Response(JSON.stringify(data), { status, headers: { 'content-type': 'application/json; charset=utf-8' } });
}

function validUsername(u) {
  return typeof u === 'string' && /^[a-zA-Z0-9_-]{3,32}$/.test(u);
}

const RATE_LIMITS = {
  register: { max: 5, windowSec: 86400 },  // 5 новых аккаунтов в сутки с одного IP
  login: { max: 20, windowSec: 3600 }      // 20 попыток входа в час с одного IP
};

const ACCOUNT_TTL_SEC = 60 * 60 * 24 * 30; // аккаунт и словарь удаляются, если не открывали 30 дней

// Продлеваем TTL не чаще раза в сутки на пользователя — иначе каждый GET /api/words
// (открытие страницы) тратит запись в KV и быстро съедает дневной лимит (1000/сутки на free-плане)
async function touchAccount(env, username) {
  const marker = 'touched:' + username;
  const alreadyTouchedToday = await env.KOTOBA_KV.get(marker);
  if (alreadyTouchedToday) return;
  const userKey = 'user:' + username;
  const wordsKey = 'words:' + username;
  const [userRaw, wordsRaw] = await Promise.all([env.KOTOBA_KV.get(userKey), env.KOTOBA_KV.get(wordsKey)]);
  const puts = [env.KOTOBA_KV.put(marker, '1', { expirationTtl: 60 * 60 * 24 })];
  if (userRaw) puts.push(env.KOTOBA_KV.put(userKey, userRaw, { expirationTtl: ACCOUNT_TTL_SEC }));
  if (wordsRaw) puts.push(env.KOTOBA_KV.put(wordsKey, wordsRaw, { expirationTtl: ACCOUNT_TTL_SEC }));
  await Promise.all(puts);
}

async function checkRateLimit(env, bucket, ip) {
  const cfg = RATE_LIMITS[bucket];
  const key = `ratelimit:${bucket}:${ip}`;
  const raw = await env.KOTOBA_KV.get(key);
  const count = raw ? parseInt(raw, 10) : 0;
  if (count >= cfg.max) return false;
  await env.KOTOBA_KV.put(key, String(count + 1), { expirationTtl: cfg.windowSec });
  return true;
}

// Для register считаем только реально созданные аккаунты, а не каждую попытку
// (неудачные из-за капчи/валидации/занятого логина квоту не тратят)
async function peekRateLimit(env, bucket, ip) {
  const cfg = RATE_LIMITS[bucket];
  const raw = await env.KOTOBA_KV.get(`ratelimit:${bucket}:${ip}`);
  const count = raw ? parseInt(raw, 10) : 0;
  return count < cfg.max;
}
async function bumpRateLimit(env, bucket, ip) {
  const cfg = RATE_LIMITS[bucket];
  const key = `ratelimit:${bucket}:${ip}`;
  const raw = await env.KOTOBA_KV.get(key);
  const count = raw ? parseInt(raw, 10) : 0;
  await env.KOTOBA_KV.put(key, String(count + 1), { expirationTtl: cfg.windowSec });
}

async function verifyTurnstile(token, secret, ip) {
  if (!token) { console.log('turnstile: no token from client'); return false; }
  if (!secret) { console.log('turnstile: TURNSTILE_SECRET is not set in env'); return false; }
  const body = new URLSearchParams();
  body.append('secret', secret);
  body.append('response', token);
  if (ip) body.append('remoteip', ip);
  try {
    const resp = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', { method: 'POST', body });
    const data = await resp.json();
    if (!data.success) console.log('turnstile siteverify failed:', JSON.stringify(data));
    return data.success === true;
  } catch (e) {
    console.log('turnstile siteverify error:', e.message);
    return false;
  }
}

export default {
  async fetch(request, env) {
    try {
      return await handle(request, env);
    } catch (e) {
      console.log('unhandled error:', e && e.message);
      if (new URL(request.url).pathname.startsWith('/api/')) {
        return json({ error: 'Сервис временно недоступен, попробуйте чуть позже' }, 503);
      }
      throw e;
    }
  }
};

async function handle(request, env) {
    const url = new URL(request.url);
    const ip = request.headers.get('cf-connecting-ip') || 'unknown';

    if (url.pathname === '/api/register' && request.method === 'POST') {
      if (!(await peekRateLimit(env, 'register', ip))) {
        return json({ error: 'Слишком много регистраций с этого адреса, попробуйте завтра' }, 429);
      }
      const body = await request.json().catch(() => null);
      if (!body || !validUsername(body.username) || typeof body.password !== 'string' || body.password.length < 6) {
        return json({ error: 'Логин: 3-32 латинских символа/цифры, пароль минимум 6 символов' }, 400);
      }
      if (!(await verifyTurnstile(body.turnstileToken, env.TURNSTILE_SECRET, ip))) {
        return json({ error: 'Не прошла проверка "я не робот", обновите страницу и попробуйте снова' }, 400);
      }
      const key = 'user:' + body.username.toLowerCase();
      const existing = await env.KOTOBA_KV.get(key);
      if (existing) return json({ error: 'Такой логин уже занят' }, 409);
      const salt = randomSaltB64();
      const hash = await hashPassword(body.password, salt);
      await env.KOTOBA_KV.put(key, JSON.stringify({ salt, hash }), { expirationTtl: ACCOUNT_TTL_SEC });
      await bumpRateLimit(env, 'register', ip);
      const token = await makeToken(body.username.toLowerCase(), env.SESSION_SECRET);
      return json({ token, username: body.username.toLowerCase() });
    }

    if (url.pathname === '/api/login' && request.method === 'POST') {
      const body = await request.json().catch(() => null);
      if (!body || !validUsername(body.username) || typeof body.password !== 'string') {
        return json({ error: 'Неверный логин или пароль' }, 400);
      }
      if (!(await checkRateLimit(env, 'login', ip))) {
        return json({ error: 'Слишком много попыток входа, попробуйте позже' }, 429);
      }
      const key = 'user:' + body.username.toLowerCase();
      const existingRaw = await env.KOTOBA_KV.get(key);
      if (!existingRaw) return json({ error: 'Неверный логин или пароль' }, 401);
      const existing = JSON.parse(existingRaw);
      const hash = await hashPassword(body.password, existing.salt);
      if (hash !== existing.hash) return json({ error: 'Неверный логин или пароль' }, 401);
      const token = await makeToken(body.username.toLowerCase(), env.SESSION_SECRET);
      await touchAccount(env, body.username.toLowerCase());
      return json({ token, username: body.username.toLowerCase() });
    }

    if (url.pathname === '/api/words' && (request.method === 'GET' || request.method === 'PUT')) {
      const auth = request.headers.get('authorization') || '';
      const token = auth.startsWith('Bearer ') ? auth.slice(7) : '';
      const username = await verifyToken(token, env.SESSION_SECRET);
      if (!username) return json({ error: 'Не авторизован' }, 401);

      if (request.method === 'GET') {
        const raw = await env.KOTOBA_KV.get('words:' + username);
        await touchAccount(env, username);
        return json({ words: raw ? JSON.parse(raw) : null });
      }

      const body = await request.json().catch(() => null);
      if (!body || !Array.isArray(body.words)) return json({ error: 'Некорректные данные' }, 400);
      if (JSON.stringify(body.words).length > 2_000_000) return json({ error: 'Слишком много данных' }, 413);
      await env.KOTOBA_KV.put('words:' + username, JSON.stringify(body.words), { expirationTtl: ACCOUNT_TTL_SEC });
      await touchAccount(env, username);
      return json({ ok: true });
    }

    return env.ASSETS.fetch(request);
}
