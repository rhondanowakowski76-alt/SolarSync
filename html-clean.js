// SolarSync — HTML cleaning for any tenant/staff-supplied HTML that is later shown
// to someone else (customer documents, compliance reports, uploaded HTML forms).
// Keeps layout and form markup; drops scripts, event handlers, javascript: URLs,
// frames, embeds and real <form> submission targets.
const sanitizeHtml = require("sanitize-html");

const OPTS = {
  allowedTags: sanitizeHtml.defaults.allowedTags.concat([
    "img", "style", "span", "div", "section", "header", "footer", "article", "main", "figure", "figcaption",
    "h1", "h2", "h3", "h4", "h5", "h6", "font", "center", "u", "s", "small", "big", "sub", "sup", "hr",
    "input", "textarea", "select", "option", "label", "fieldset", "legend",
    "colgroup", "col", "svg", "path", "rect", "circle", "line", "polyline", "polygon", "g", "text",
  ]),
  allowedAttributes: {
    "*": ["style", "class", "id", "title", "align", "valign", "width", "height", "colspan", "rowspan",
      "border", "cellpadding", "cellspacing", "bgcolor", "color", "dir", "lang", "role", "aria-label", "data-*"],
    a: ["href", "name", "target", "rel"],
    img: ["src", "alt"],
    font: ["face", "size", "color"],
    input: ["type", "name", "value", "checked", "placeholder", "readonly", "disabled", "size", "maxlength"],
    textarea: ["name", "rows", "cols", "placeholder", "readonly", "disabled"],
    select: ["name", "multiple", "disabled"],
    option: ["value", "selected"],
    label: ["for"],
    svg: ["viewBox", "xmlns", "fill", "stroke", "stroke-width", "preserveAspectRatio"],
    path: ["d", "fill", "stroke", "stroke-width"],
    rect: ["x", "y", "rx", "ry", "fill", "stroke"],
    circle: ["cx", "cy", "r", "fill", "stroke"],
    line: ["x1", "y1", "x2", "y2", "stroke"],
    polyline: ["points", "fill", "stroke"], polygon: ["points", "fill", "stroke"],
    g: ["fill", "stroke", "transform"], text: ["x", "y", "fill", "font-size", "text-anchor"],
  },
  allowedSchemes: ["http", "https", "mailto", "tel"],
  allowedSchemesByTag: { img: ["https", "http", "data"] },
  allowProtocolRelative: false,
  // <style> blocks are kept for document layout; their text cannot run script.
  allowVulnerableTags: true,
};

function cleanHtml(html) {
  if (html == null) return html;
  return sanitizeHtml(String(html), OPTS);
}

// Plain-text field (letterhead name, address…): stored as plain text (angle brackets
// and control characters removed, length-capped); it is HTML-escaped wherever it's shown.
function cleanText(v, max = 300) {
  if (v == null) return null;
  // Angle brackets are dropped outright (no tag-matching regex to get around).
  return String(v).replace(/[<>]/g, "").replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f]/g, "").slice(0, max);
}

// Logo / image URL: an inline raster image or an https URL only.
const SAFE_IMG = /^(data:image\/(png|jpe?g|webp|gif|svg\+xml);base64,[A-Za-z0-9+/=\s]+$|https:\/\/[^\s"'<>]+$)/;
function safeImageUrl(v) {
  if (v == null || v === "") return null;
  return SAFE_IMG.test(String(v)) ? String(v) : undefined;   // undefined = reject
}

module.exports = { cleanHtml, cleanText, safeImageUrl };
