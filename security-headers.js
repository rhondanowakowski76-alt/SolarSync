// SolarSync — browser security headers on every response.
//
// The Content-Security-Policy only lets the pages load scripts from this site, fonts
// from Google Fonts, and talk to this site plus the address-lookup service. Pages
// can't be framed by other sites (clickjacking), plugins are off, and forms can only
// post back here. Inline scripts are still allowed because the app ships as one
// precompiled page; injected markup is stopped by the HTML cleaning in html-clean.js
// and the escaping in the page itself.
function csp({ devCompile }) {
  return [
    "default-src 'self'",
    // devCompile: no dist/ build, so the page compiles itself in the browser (Babel needs eval).
    "script-src 'self' 'unsafe-inline'" + (devCompile ? " 'unsafe-eval'" : ""),
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
    "font-src 'self' data: https://fonts.gstatic.com",
    // Logos and photos are data: URLs or https images; maps come from ArcGIS tiles.
    "img-src 'self' data: blob: https:",
    "media-src 'self' data: blob:",
    "connect-src 'self' https://nominatim.openstreetmap.org",
    "worker-src 'self' blob:",
    "frame-src 'self' blob: data:",
    "manifest-src 'self'",
    "object-src 'none'",
    "base-uri 'self'",
    "form-action 'self'",
    "frame-ancestors 'none'",
  ].join("; ");
}

function securityHeaders({ devCompile = false } = {}) {
  const policy = csp({ devCompile });
  const prod = process.env.NODE_ENV === "production";
  return (req, res, next) => {
    res.setHeader("Content-Security-Policy", policy);
    res.setHeader("X-Content-Type-Options", "nosniff");
    res.setHeader("X-Frame-Options", "DENY");
    res.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");
    // Camera (site photos) and location (site address) stay available to the app itself.
    res.setHeader("Permissions-Policy", "camera=(self), geolocation=(self), microphone=(), payment=(), usb=(), interest-cohort=()");
    // Print/preview pop-ups are same-site, so only the opener link to other sites is cut.
    res.setHeader("Cross-Origin-Opener-Policy", "same-origin-allow-popups");
    res.setHeader("X-Permitted-Cross-Domain-Policies", "none");
    if (prod) res.setHeader("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
    // API answers (customer data, tokens) must never sit in a shared or browser cache.
    if (req.path.startsWith("/api/")) res.setHeader("Cache-Control", "no-store");
    next();
  };
}

module.exports = { securityHeaders };
