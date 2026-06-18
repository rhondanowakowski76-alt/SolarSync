// SolarSync backend — DigitalOcean Spaces (S3-compatible) wrapper.
//
// Configured by 5 env vars set in DO App Platform → solarsync app → Settings →
// App-Level Environment Variables (mark SPACES_SECRET as encrypted):
//   SPACES_ENDPOINT  e.g. https://syd1.digitaloceanspaces.com
//   SPACES_REGION    e.g. syd1
//   SPACES_BUCKET    e.g. solarsync-tenant-docs
//   SPACES_KEY       Spaces access key id
//   SPACES_SECRET    Spaces secret access key
//
// If any of these are missing, isConfigured() returns false and the document-library
// endpoints respond with 503 "storage_not_configured" so the UI shows a friendly
// "Document library not yet enabled" message instead of crashing.

const { S3Client, PutObjectCommand, GetObjectCommand, DeleteObjectCommand } = require("@aws-sdk/client-s3");
const { getSignedUrl } = require("@aws-sdk/s3-request-presigner");

let _client = null;

function isConfigured() {
  return !!(process.env.SPACES_ENDPOINT && process.env.SPACES_REGION
    && process.env.SPACES_BUCKET && process.env.SPACES_KEY && process.env.SPACES_SECRET);
}

function client() {
  if (_client) return _client;
  if (!isConfigured()) return null;
  _client = new S3Client({
    endpoint: process.env.SPACES_ENDPOINT,
    region: process.env.SPACES_REGION,
    credentials: {
      accessKeyId: process.env.SPACES_KEY,
      secretAccessKey: process.env.SPACES_SECRET,
    },
    forcePathStyle: false,
  });
  return _client;
}

function bucket() { return process.env.SPACES_BUCKET; }

// One tenant per folder, plus a doc_group/version path so re-uploads don't clobber.
function makeKey(tenant_id, doc_group, version, filename) {
  const safe = String(filename).replace(/[^A-Za-z0-9._-]+/g, "_").slice(0, 120);
  return `tenants/${tenant_id}/${doc_group}/v${version}-${safe}`;
}

async function putObject(key, buffer, mime) {
  const c = client();
  if (!c) throw new Error("storage_not_configured");
  await c.send(new PutObjectCommand({
    Bucket: bucket(), Key: key, Body: buffer, ContentType: mime || "application/octet-stream",
    ACL: "private",
  }));
  return key;
}

async function deleteObject(key) {
  const c = client();
  if (!c) throw new Error("storage_not_configured");
  await c.send(new DeleteObjectCommand({ Bucket: bucket(), Key: key }));
}

// Presigned URL valid for 5 minutes. Browser downloads directly from Spaces.
async function presignDownload(key, filename) {
  const c = client();
  if (!c) throw new Error("storage_not_configured");
  const cmd = new GetObjectCommand({
    Bucket: bucket(), Key: key,
    ResponseContentDisposition: `attachment; filename="${String(filename).replace(/[^A-Za-z0-9._-]+/g, "_")}"`,
  });
  return await getSignedUrl(c, cmd, { expiresIn: 300 });
}

module.exports = { isConfigured, putObject, deleteObject, presignDownload, makeKey };
