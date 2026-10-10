// SolarSync — passkey sign-in (WebAuthn / FIDO2).
//
// A passkey is a phishing-resistant sign-in: Face ID, fingerprint, the device PIN or a
// security key unlocks a key that never leaves the device and only works on this
// site's address. It replaces PIN + authenticator code for whoever sets one up; the
// PIN + code sign-in keeps working as the fallback.
//
// Settings (optional, on the server): PASSKEY_RP_ID (e.g. app.solarsync.com.au) and
// PASSKEY_ORIGIN (e.g. https://app.solarsync.com.au). By default both come from the
// address the browser used.
const jwt = require("jsonwebtoken");
const {
  generateRegistrationOptions, verifyRegistrationResponse,
  generateAuthenticationOptions, verifyAuthenticationResponse,
} = require("@simplewebauthn/server");
const A = require("./auth");
const { rows, one, run, rid, audit } = require("./db");

const b64u = (buf) => Buffer.from(buf).toString("base64url");
const unb64u = (s) => new Uint8Array(Buffer.from(String(s), "base64url"));

function site(req) {
  const proto = String(req.headers["x-forwarded-proto"] || req.protocol || "https").split(",")[0];
  const host = req.get("host") || "";
  return {
    rpID: process.env.PASSKEY_RP_ID || host.split(":")[0],
    origin: process.env.PASSKEY_ORIGIN || (proto + "://" + host),
  };
}

// Each challenge is used once: remembered until it expires.
const usedChallenges = new Map();
function useChallenge(ch) {
  const now = Date.now();
  for (const [k, t] of usedChallenges) if (t < now) usedChallenges.delete(k);
  if (usedChallenges.has(ch)) return false;
  usedChallenges.set(ch, now + 10 * 60 * 1000);
  return true;
}
const sealState = (o) => jwt.sign(o, A.JWT_SECRET, { expiresIn: "5m" });
function openState(s, typ) {
  try { const p = jwt.verify(String(s || ""), A.JWT_SECRET); return p.typ === typ ? p : null; } catch (e) { return null; }
}

function register(app, { h, ok, loginBlocked }) {
  // A real person signed in to their own account (not a support session or beta tester).
  const self = async (req, res) => {
    if (req.user.support || String(req.user.sub || "").startsWith("tester-")) { res.status(403).json({ error: "not_available" }); return null; }
    const u = await one("select * from users where id=$1", [req.user.sub]);
    if (!u) { res.status(404).json({ error: "not_found" }); return null; }
    return u;
  };

  app.get("/api/auth/passkeys", A.authRequired, h(async (req, res) => {
    const u = await self(req, res); if (!u) return;
    ok(res, await rows("select id, name, created_at, last_used_at from passkeys where user_id=$1 order by created_at", [u.id]));
  }));

  app.post("/api/auth/passkeys/options", A.authRequired, h(async (req, res) => {
    const u = await self(req, res); if (!u) return;
    const { rpID } = site(req);
    const existing = await rows("select credential_id, transports from passkeys where user_id=$1", [u.id]);
    const options = await generateRegistrationOptions({
      rpName: "SolarSync", rpID, userName: u.display_name, userDisplayName: u.display_name,
      userID: new TextEncoder().encode(u.id), attestationType: "none",
      excludeCredentials: existing.map(c => ({ id: c.credential_id, transports: c.transports ? String(c.transports).split(",") : undefined })),
      authenticatorSelection: { residentKey: "required", userVerification: "required" },
    });
    ok(res, { options, state: sealState({ typ: "pk_reg", sub: u.id, ch: options.challenge }) });
  }));

  app.post("/api/auth/passkeys", A.authRequired, h(async (req, res) => {
    const u = await self(req, res); if (!u) return;
    const st = openState(req.body && req.body.state, "pk_reg");
    if (!st || st.sub !== u.id || !useChallenge(st.ch)) return res.status(400).json({ error: "expired" });
    const { rpID, origin } = site(req);
    let v;
    try {
      v = await verifyRegistrationResponse({ response: req.body.response, expectedChallenge: st.ch,
        expectedOrigin: origin, expectedRPID: rpID, requireUserVerification: true });
    } catch (e) { return res.status(400).json({ error: "not_verified" }); }
    if (!v.verified || !v.registrationInfo) return res.status(400).json({ error: "not_verified" });
    const c = v.registrationInfo.credential;
    if (await one("select 1 from passkeys where credential_id=$1", [c.id])) return res.status(409).json({ error: "already_registered" });
    const id = "pk-" + rid().slice(0, 10);
    const name = String((req.body && req.body.name) || "Passkey").replace(/[<>]/g, "").slice(0, 60) || "Passkey";
    await run(`insert into passkeys (id, user_id, credential_id, public_key, counter, transports, name)
      values ($1,$2,$3,$4,$5,$6,$7)`,
      [id, u.id, c.id, b64u(c.publicKey), c.counter || 0, (c.transports || []).join(",") || null, name]);
    await audit(u.id, "passkey_added", id, u.tenant_id);
    ok(res, { id, name });
  }));

  app.delete("/api/auth/passkeys/:id", A.authRequired, h(async (req, res) => {
    const u = await self(req, res); if (!u) return;
    const pk = await one("select * from passkeys where id=$1 and user_id=$2", [req.params.id, u.id]);
    if (!pk) return res.status(404).json({ error: "not_found" });
    await run("delete from passkeys where id=$1", [pk.id]);
    await audit(u.id, "passkey_removed", pk.id, u.tenant_id);
    ok(res, { ok: true });
  }));

  // Sign-in, step 1: a challenge for the device. No name needed — the passkey says who it is.
  app.post("/api/auth/passkey/options", h(async (req, res) => {
    const { rpID } = site(req);
    const options = await generateAuthenticationOptions({ rpID, userVerification: "required", allowCredentials: [] });
    ok(res, { options, state: sealState({ typ: "pk_auth", ch: options.challenge }) });
  }));

  // Sign-in, step 2: check the device's signature and issue the session.
  app.post("/api/auth/passkey/verify", h(async (req, res) => {
    const st = openState(req.body && req.body.state, "pk_auth");
    const response = req.body && req.body.response;
    if (!st || !response || !response.id) return res.status(400).json({ error: "expired" });
    const pk = await one("select * from passkeys where credential_id=$1", [String(response.id)]);
    if (!pk) return res.status(401).json({ error: "unknown_passkey" });
    const u = await one("select * from users where id=$1", [pk.user_id]);
    if (!u) return res.status(401).json({ error: "unknown_passkey" });
    if (await loginBlocked(u, res)) return;
    if (A.lockedOut(u)) return res.status(429).json({ error: "locked", until: u.locked_until });
    if (!useChallenge(st.ch)) return res.status(400).json({ error: "expired" });
    const { rpID, origin } = site(req);
    let v;
    try {
      v = await verifyAuthenticationResponse({ response, expectedChallenge: st.ch, expectedOrigin: origin,
        expectedRPID: rpID, requireUserVerification: true,
        credential: { id: pk.credential_id, publicKey: unb64u(pk.public_key), counter: Number(pk.counter) || 0,
          transports: pk.transports ? String(pk.transports).split(",") : undefined } });
    } catch (e) { return res.status(401).json({ error: "not_verified" }); }
    if (!v.verified) return res.status(401).json({ error: "not_verified" });
    await run("update passkeys set counter=$1, last_used_at=now() where id=$2", [v.authenticationInfo.newCounter || 0, pk.id]);
    await audit(u.id, "login_passkey", pk.id, u.tenant_id);
    ok(res, {
      access_token: A.mintAccess(u), refresh_token: A.mintRefresh(u),
      user: { id: u.id, display_name: u.display_name, app_role: u.app_role, tenant_id: u.tenant_id },
    });
  }));
}

module.exports = { register };
