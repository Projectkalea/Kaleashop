import 'dotenv/config';
import express from 'express';
import crypto from 'node:crypto';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

/* ------------------------------------------------------------------ */
/*  Config                                                              */
/* ------------------------------------------------------------------ */
const PORT        = Number(process.env.PORT || 3000);
const BASE_URL    = (process.env.BASE_URL || `http://localhost:${PORT}`).replace(/\/+$/, '');
const CLIENT_ID   = process.env.DISCORD_CLIENT_ID || '';
const CLIENT_SEC  = process.env.DISCORD_CLIENT_SECRET || '';
const SESSION_SEC = process.env.SESSION_SECRET || 'dev-insecure-secret';
const GUILD_ID    = process.env.GUILD_ID || '';

/* Porte d'entrée : vrai site privé. GATE=false pour tout ouvrir. */
const GATE        = (process.env.GATE ?? 'true') !== 'false';
/* Échappe d'urgence : /?token=XXX donne un accès sans Discord.
   Laisse vide pour désactiver. */
const GATE_TOKEN  = process.env.GATE_TOKEN || '';

const SCOPES = ['identify', 'guilds'];
const REDIRECT_URI = `${BASE_URL}/auth/callback`;
const API = 'https://discord.com/api/v10';

if (!CLIENT_ID || !CLIENT_SEC) {
  console.warn(
    '\n[!] DISCORD_CLIENT_ID / DISCORD_CLIENT_SECRET manquants dans .env\n' +
    '    -> copie .env.example vers .env et remplis tes identifiants.\n'
  );
}

/* ------------------------------------------------------------------ */
/*  Sessions signées (HMAC-SHA256)                                      */
/* ------------------------------------------------------------------ */
const hmac = (d) => crypto.createHmac('sha256', SESSION_SEC).update(d).digest('base64url');

function createSession(payload) {
  const body = Buffer.from(JSON.stringify({ ...payload, exp: Date.now() + 30 * 864e5 }))
    .toString('base64url');
  return `${body}.${hmac(body)}`;
}

function readSession(cookie) {
  if (!cookie) return null;
  const i = cookie.lastIndexOf('.');
  if (i < 0) return null;
  const body = cookie.slice(0, i);
  const mac  = Buffer.from(cookie.slice(i + 1));
  const want = Buffer.from(hmac(body));
  if (mac.length !== want.length || !crypto.timingSafeEqual(mac, want)) return null;
  try {
    const data = JSON.parse(Buffer.from(body, 'base64url').toString('utf8'));
    if (!data.exp || data.exp < Date.now()) return null;
    return data;
  } catch { return null; }
}

function parseCookies(req) {
  const out = {};
  for (const part of (req.headers.cookie || '').split(';')) {
    const k = part.indexOf('=');
    if (k > 0) out[part.slice(0, k).trim()] = decodeURIComponent(part.slice(k + 1).trim());
  }
  return out;
}

const SESSION_COOKIE = 'kalea_session';

const cookieOpts = (maxAge) =>
  `HttpOnly; Path=/; SameSite=Lax; Max-Age=${maxAge}` + (BASE_URL.startsWith('https') ? '; Secure' : '');

const b64url = (b) => Buffer.from(b).toString('base64url');
const pkceVerifier  = () => b64url(crypto.randomBytes(32));
const pkceChallenge = (v) => b64url(crypto.createHash('sha256').update(v).digest());

/* ------------------------------------------------------------------ */
/*  Discord API                                                         */
/* ------------------------------------------------------------------ */
async function tokenRequest(params) {
  const res = await fetch(`${API}/oauth2/token`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ client_id: CLIENT_ID, client_secret: CLIENT_SEC, ...params }),
  });
  if (!res.ok) throw new Error(`token ${res.status}: ${await res.text()}`);
  return res.json();
}

const exchangeCode = (code, verifier) => tokenRequest({
  grant_type: 'authorization_code',
  code,
  redirect_uri: REDIRECT_URI,
  code_verifier: verifier,
});

const refreshAccessToken = (refresh_token) => tokenRequest({
  grant_type: 'refresh_token',
  refresh_token,
});

async function discordGet(token, endpoint) {
  const res = await fetch(`${API}${endpoint}`, { headers: { Authorization: `Bearer ${token.access_token}` } });
  return res.ok ? res.json() : null;
}

const avatarUrl = (u, size = 64) =>
  u.avatar
    ? `https://cdn.discordapp.com/avatars/${u.id}/${u.avatar}.png?size=${size}`
    : `https://cdn.discordapp.com/embed/avatars/${Number(BigInt(u.id) >> 22n) % 6}.png`;

/* Résout la session : renouvelle le jeton Discord si expiré. */
async function resolveSession(req, res) {
  const s = readSession(parseCookies(req)[SESSION_COOKIE]);
  if (!s) return null;
  if (s.bypass) return s;                       // accès d'urgence, pas de jeton

  const obtainedAt = s.obtained_at || 0;
  const expiresIn  = (s.expires_in || 0) * 1000;
  if (obtainedAt + expiresIn - 60_000 > Date.now()) return s;   // encore bon

  if (!s.refresh_token) return null;
  try {
    const fresh = await refreshAccessToken(s.refresh_token);
    const merged = { ...s, ...fresh, obtained_at: Date.now() };
    res.setHeader('Set-Cookie', `${SESSION_COOKIE}=${createSession(merged)}; ${cookieOpts(30 * 86400)}`);
    return merged;
  } catch (e) {
    console.warn('[auth] refresh impossible:', e.message);
    res.clearCookie(SESSION_COOKIE);
    return null;
  }
}

/* ------------------------------------------------------------------ */
/*  App                                                                 */
/* ------------------------------------------------------------------ */
const app = express();
app.use(express.static(path.join(__dirname, 'public'), { index: false }));

const sessionOf = (req) => readSession(parseCookies(req)[SESSION_COOKIE]);

/* --- Porte d'entrée : le site est privé --- */
function gate(req, res, next) {
  if (!GATE) return next();
  if (sessionOf(req)) return next();
  if (GATE_TOKEN && req.query.token === GATE_TOKEN) {
    res.setHeader('Set-Cookie', `${SESSION_COOKIE}=${createSession({ bypass: 1 })}; ${cookieOpts(30 * 86400)}`);
    return res.redirect('/');
  }
  res.redirect('/auth/login');
}

app.get('/', gate, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

/* --- /api/me : profil (et renouvellement automatique du jeton) --- */
app.get('/api/me', async (req, res) => {
  const s = await resolveSession(req, res);
  if (!s) return res.json({ user: null });

  if (s.bypass) {
    return res.json({
      user: { id: '0', username: 'owner', global_name: 'Owner', avatar: null },
      isMember: true, bypass: true,
    });
  }

  const [me, guilds] = await Promise.all([
    discordGet(s, '/users/@me'),
    discordGet(s, '/users/@me/guilds'),
  ]);
  if (!me) {
    res.clearCookie(SESSION_COOKIE);
    return res.json({ user: null });
  }

  res.json({
    user: {
      id: me.id,
      username: me.username,
      global_name: me.global_name || me.username,
      avatar: avatarUrl(me),
    },
    isMember: GUILD_ID ? (guilds || []).some((g) => g.id === GUILD_ID) : null,
  });
});

/* --- /auth/login : redirige vers Discord --- */
app.get('/auth/login', (req, res) => {
  if (!CLIENT_ID || !CLIENT_SEC) return res.redirect('/auth/error?e=config');

  const verifier = pkceVerifier();
  const state    = b64url(crypto.randomBytes(16));

  const params = new URLSearchParams({
    client_id: CLIENT_ID,
    redirect_uri: REDIRECT_URI,
    response_type: 'code',
    scope: SCOPES.join(' '),
    state,
    code_challenge: pkceChallenge(verifier),
    code_challenge_method: 'S256',
  });

  res.setHeader('Set-Cookie', [
    `pkce=${verifier}; ${cookieOpts(600)}`,
    `oauth_state=${state}; ${cookieOpts(600)}`,
  ]);
  res.redirect(`https://discord.com/oauth2/authorize?${params}`);
});

/* --- /auth/callback : échange le code contre un jeton --- */
app.get('/auth/callback', async (req, res) => {
  const { code, state, error } = req.query;
  const cookies = parseCookies(req);

  if (error || !code) return res.redirect(`/auth/error?e=${encodeURIComponent(error || 'no_code')}`);
  if (!state || state !== cookies.oauth_state) return res.redirect('/auth/error?e=state');

  try {
    const token = await exchangeCode(String(code), cookies.pkce);
    const payload = { ...token, obtained_at: Date.now() };
    res.setHeader('Set-Cookie', [
      `${SESSION_COOKIE}=${createSession(payload)}; ${cookieOpts(30 * 86400)}`,
      'pkce=; ' + cookieOpts(0),
      'oauth_state=; ' + cookieOpts(0),
    ]);
    res.redirect('/');
  } catch (err) {
    console.error('[auth] échec:', err.message);
    res.redirect('/auth/error?e=exchange');
  }
});

/* --- /auth/logout --- */
app.post('/auth/logout', (req, res) => {
  res.setHeader('Set-Cookie', `${SESSION_COOKIE}=; ${cookieOpts(0)}`);
  res.json({ ok: true });
});

/* --- /auth/error : page d'erreur, évite la boucle de redirection --- */
const ERRORS = {
  config:  'Le serveur n\'est pas configuré : DISCORD_CLIENT_ID / DISCORD_CLIENT_SECRET absents du .env.',
  state:   'Session de sécurité expirée. Réessaie la connexion.',
  exchange:'L\'échange du code a échoué. Vérifie le Redirect URI dans le Developer Portal Discord.',
  access_denied: 'Connexion annulée sur Discord.',
  login_required: 'Discord demande une reconnexion.',
  no_code: 'Discord n\'a pas renvoyé de code.',
};

app.get('/auth/error', (req, res) => {
  const msg = ERRORS[req.query.e] || 'Erreur inconnue.';
  res.status(200).send(`<!DOCTYPE html><html lang="fr"><head><meta charset="utf-8">
<title>Kalea — erreur de connexion</title>
<style>
 body{margin:0;min-height:100vh;display:grid;place-items:center;background:#0a0a0c;color:#f3f3f5;
      font-family:system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
 .box{max-width:440px;padding:32px;background:#141417;border:1px solid rgba(255,255,255,.09);border-radius:16px}
 h1{font-size:20px;margin:0 0 12px} p{color:#9a9aa4;font-size:14px;line-height:1.6;margin:0 0 20px}
 a{display:inline-block;background:#5865F2;color:#fff;text-decoration:none;font-weight:700;font-size:14px;
   padding:10px 18px;border-radius:999px}
</style></head><body><div class="box">
<h1>Connexion impossible</h1><p>${msg}</p>
<a href="/auth/login">Réessayer</a>
</div></body></html>`);
});

app.listen(PORT, () => {
  console.log(`\n  Kalea Store  → ${BASE_URL}`);
  console.log(`  Redirect URI → ${REDIRECT_URI}`);
  console.log(`  Porte privée → ${GATE ? 'activée (login Discord obligatoire)' : 'désactivée'}`);
  console.log(`  Échappe urgence → ${GATE_TOKEN ? 'active (utilise ?token=...)' : 'désactivée'}\n`);
});
