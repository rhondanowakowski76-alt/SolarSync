// SolarSync backend — PIN + TOTP auth helpers (NO email). TOTP verified vs RFC 6238.
// Pure crypto/JWT helpers only — DB writes live in server.js (async).
const crypto = require("crypto");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

// Never sign with a guessable secret in production. If JWT_SECRET is missing (or too
// short) on a live server, use a random per-boot secret instead: everyone has to sign
// in again after a restart, but nobody can forge a token from a public default.
const JWT_SECRET = (() => {
  const s = process.env.JWT_SECRET || "";
  if (s.length >= 32) return s;
  if (process.env.NODE_ENV === "production") {
    console.error("[security] JWT_SECRET is missing or shorter than 32 characters — using a random per-boot secret. Set JWT_SECRET to keep sessions across restarts.");
    return crypto.randomBytes(48).toString("hex");
  }
  return s || "dev-only-change-me";
})();
const PIN_TICKET_TTL = "10m";
const ACCESS_TTL = "15m";
const REFRESH_TTL = "30d";

// ---------- TOTP (RFC 6238, SHA-1, 6 digits, 30s) ----------
const B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
function randomBase32(len = 20) {
  const bytes = crypto.randomBytes(len);
  let out = ""; for (const b of bytes) out += B32[b % 32]; return out;
}
function base32ToBuf(s) {
  let bits = ""; const out = [];
  for (const c of s.replace(/=+$/, "").toUpperCase()) {
    const v = B32.indexOf(c); if (v < 0) continue; bits += v.toString(2).padStart(5, "0");
  }
  for (let i = 0; i + 8 <= bits.length; i += 8) out.push(parseInt(bits.slice(i, i + 8), 2));
  return Buffer.from(out);
}
function totpAt(secret, counter) {
  const msg = Buffer.alloc(8); let c = counter;
  for (let i = 7; i >= 0; i--) { msg[i] = c & 0xff; c = Math.floor(c / 256); }
  const h = crypto.createHmac("sha1", base32ToBuf(secret)).update(msg).digest();
  const o = h[19] & 0xf;
  const bin = ((h[o] & 0x7f) << 24) | (h[o + 1] << 16) | (h[o + 2] << 8) | h[o + 3];
  return (bin % 1_000_000).toString().padStart(6, "0");
}
function verifyTotp(secret, code) {
  const step = Math.floor(Date.now() / 1000 / 30);
  for (const w of [-1, 0, 1]) if (totpAt(secret, step + w) === String(code)) return true;
  return false;
}
function otpauthUri(name, secret) {
  const issuer = encodeURIComponent("SolarSync");
  const label = encodeURIComponent(name);
  // Explicit standard params (SHA1/6/30) → identical behaviour in Microsoft
  // Authenticator, Google Authenticator, Authy, 1Password, etc.
  return `otpauth://totp/${issuer}:${label}?secret=${secret}&issuer=${issuer}&algorithm=SHA1&digits=6&period=30`;
}

// ---------- JWT ----------
function mintAccess(u) {
  return jwt.sign(
    { sub: u.id, app_role: u.app_role, tenant_id: u.tenant_id || "", display_name: u.display_name },
    JWT_SECRET, { expiresIn: ACCESS_TTL });
}
// `tv` = the user's token_version; bumping it (admin reset) kills every refresh token.
function mintRefresh(u) { return jwt.sign({ sub: u.id, typ: "refresh", tv: u.token_version || 0 }, JWT_SECRET, { expiresIn: REFRESH_TTL }); }
// Short-lived proof that the PIN step passed — required before the authenticator
// step (or first-time enrolment) can issue a session.
function mintPinTicket(u) { return jwt.sign({ sub: u.id, typ: "pin_ok" }, JWT_SECRET, { expiresIn: PIN_TICKET_TTL }); }
function pinTicketOk(ticket, userId) {
  try { const p = jwt.verify(String(ticket || ""), JWT_SECRET); return p.typ === "pin_ok" && p.sub === userId; }
  catch { return false; }
}
function verify(token) { return jwt.verify(token, JWT_SECRET); }

// ---------- middleware ----------
function authRequired(req, res, next) {
  const h = req.headers.authorization || "";
  const tok = h.startsWith("Bearer ") ? h.slice(7) : null;
  if (!tok) return res.status(401).json({ error: "no_token" });
  // Only access tokens carry no `typ`; refresh, PIN-ticket and tester tokens are not sessions.
  try { const p = verify(tok); if (p.typ) throw new Error("wrong_type"); req.user = p; next(); }
  catch { return res.status(401).json({ error: "bad_token" }); }
}
function requireRole(...roles) {
  return (req, res, next) => roles.includes(req.user.app_role) ? next() : res.status(403).json({ error: "forbidden" });
}

// ---------- anti-brute-force (pure check; DB writes done in server.js) ----------
function lockedOut(u) { return u.locked_until && new Date(u.locked_until) > new Date(); }

module.exports = {
  bcrypt, randomBase32, verifyTotp, otpauthUri,
  mintAccess, mintRefresh, mintPinTicket, pinTicketOk, verify, authRequired, requireRole,
  lockedOut, JWT_SECRET,
};
