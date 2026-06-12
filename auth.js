// SolarSync backend — PIN + TOTP auth (NO email). TOTP verified vs RFC 6238.
const crypto = require("crypto");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { db } = require("./db");

const JWT_SECRET = process.env.JWT_SECRET || "dev-only-change-me";
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
  return `otpauth://totp/${issuer}:${label}?secret=${secret}&issuer=${issuer}&digits=6&period=30`;
}

// ---------- JWT ----------
function mintAccess(u) {
  return jwt.sign(
    { sub: u.id, app_role: u.app_role, tenant_id: u.tenant_id || "", display_name: u.display_name },
    JWT_SECRET, { expiresIn: ACCESS_TTL });
}
function mintRefresh(u) { return jwt.sign({ sub: u.id, typ: "refresh" }, JWT_SECRET, { expiresIn: REFRESH_TTL }); }
function verify(token) { return jwt.verify(token, JWT_SECRET); }

// ---------- middleware ----------
function authRequired(req, res, next) {
  const h = req.headers.authorization || "";
  const tok = h.startsWith("Bearer ") ? h.slice(7) : null;
  if (!tok) return res.status(401).json({ error: "no_token" });
  try { req.user = verify(tok); next(); }
  catch { return res.status(401).json({ error: "bad_token" }); }
}
function requireRole(...roles) {
  return (req, res, next) => roles.includes(req.user.app_role) ? next() : res.status(403).json({ error: "forbidden" });
}

// ---------- anti-brute-force ----------
function lockedOut(u) { return u.locked_until && new Date(u.locked_until) > new Date(); }
function bumpFail(u) {
  const n = (u.failed_attempts || 0) + 1;
  if (n >= 5) db.prepare("update users set failed_attempts=0, locked_until=? where id=?")
    .run(new Date(Date.now() + 5 * 60000).toISOString(), u.id);
  else db.prepare("update users set failed_attempts=? where id=?").run(n, u.id);
}
function clearFail(id) { db.prepare("update users set failed_attempts=0, locked_until=null where id=?").run(id); }

module.exports = {
  bcrypt, randomBase32, verifyTotp, otpauthUri,
  mintAccess, mintRefresh, verify, authRequired, requireRole,
  lockedOut, bumpFail, clearFail, JWT_SECRET,
};
