/* SolarSync service worker — lets the app load on remote sites with no signal.
   Strategy:
   - Navigations (opening /app) are network-first so an online device always gets
     the freshest bundle; when there is no signal we fall back to the cached shell.
   - Same-origin static assets (vendor libraries, fonts) are cache-first.
   - /api/* is never cached — live data always goes to the network, and offline
     writes are handled by window.ssOffline (the localStorage queue), not here. */
const VERSION = "solarsync-v2";
const SHELL = ["/app", "/"];

self.addEventListener("install", (e) => {
  e.waitUntil(
    caches.open(VERSION)
      .then((c) => c.addAll(SHELL).catch(() => {}))
      .then(() => self.skipWaiting())
  );
});

self.addEventListener("activate", (e) => {
  e.waitUntil(
    caches.keys()
      .then((keys) => Promise.all(keys.filter((k) => k !== VERSION).map((k) => caches.delete(k))))
      .then(() => self.clients.claim())
  );
});

self.addEventListener("fetch", (e) => {
  const req = e.request;
  if (req.method !== "GET") return; // writes go to the network / ssOffline queue, never the cache
  const url = new URL(req.url);

  // Never cache the API — always hit the network for live data.
  if (url.origin === location.origin && url.pathname.startsWith("/api/")) return;

  // Opening the app: network-first, fall back to the cached shell when offline.
  if (req.mode === "navigate") {
    e.respondWith(
      fetch(req)
        .then((res) => { const copy = res.clone(); caches.open(VERSION).then((c) => c.put(req, copy)); return res; })
        .catch(() => caches.match(req).then((m) => m || caches.match("/app").then((s) => s || caches.match("/"))))
    );
    return;
  }

  // Static assets (same-origin vendor libs, icons) and fonts: cache-first, refresh in the background.
  e.respondWith(
    caches.match(req).then((m) =>
      m || fetch(req)
        .then((res) => { const copy = res.clone(); caches.open(VERSION).then((c) => c.put(req, copy)); return res; })
        .catch(() => m)
    )
  );
});
