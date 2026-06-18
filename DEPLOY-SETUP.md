# SolarSync — Deployment Setup (Document Library + Form Autofill)

This is the checklist to turn on the Document Library and the
"fill a form from a customer's details" feature in production.
Do this once in DigitalOcean.

## 1. Create a Spaces bucket (one-time)

- DigitalOcean → **Spaces Object Storage** → **Create Spaces Bucket**.
- Pick a region (Sydney = `syd1`) and a bucket name.
- API → **Spaces Keys** → **Generate New Key**. Copy the **secret now** —
  it is shown only once.

## 2. Set 5 App-Level environment variables

DigitalOcean → your App → **Settings** → **App-Level Environment Variables**.
Fill in the three bracketed values; the other two are fixed for Sydney.

```
SPACES_ENDPOINT = https://syd1.digitaloceanspaces.com
SPACES_REGION   = syd1
SPACES_BUCKET   = [your-bucket-name]
SPACES_KEY      = [your-spaces-access-key]
SPACES_SECRET   = [your-spaces-secret]   <- tick "Encrypt"
```

- If you create the bucket in another region, swap `syd1` in BOTH
  `SPACES_ENDPOINT` and `SPACES_REGION` (e.g. `sgp1`, `nyc3`). The
  endpoint is always `https://<region>.digitaloceanspaces.com`.
- Set these as **App-Level** (not component-scoped) so the backend reads them.

## 3. Redeploy

Saving env vars usually triggers a deploy. If not, hit **Deploy**.
The latest code is already on `main`.

## 4. Test it (hard-reload the page first)

1. Log in as the **installer** → **Documents** tab. If the upload area is
   active (no locked/add-on message), storage connected fine.
2. Upload an **HTML-based `.doc` form** (the `SolarSync-OwnerManual-*.doc`
   files in this repo work as test forms).
3. A **Fill** button appears on it → click → pick **Adam Smith** →
   confirm name / site address / system auto-fill, and that
   installer / SAA / NMI fields stay highlighted → edit → **Save** sends it.
4. Log in as the **customer** → **Documents → "From your installer"** →
   **View** shows the filled form (print / save-PDF available).

## Gotchas

- **Region mismatch** between the bucket and the env vars → 403/redirect on
  upload. Make them match.
- If Documents still shows **locked / add-on required** after deploy, the
  env vars didn't take — recheck spelling and that the deploy finished.
- **Binary `.docx` / `.pdf` are download-only** by design (no Office engine).
  Only HTML-based forms get the autofill + in-browser edit. This is the
  format the SolarSync manuals and the portal's own generated forms use.

## How the feature works (reference)

- On upload, an HTML file (mime `text/html`, or an `.htm/.html/.doc` that
  actually starts with `<html>`/`<!doctype html>`) has its markup stored in
  `tenant_documents.content_html` and is flagged `fillable`.
- "Fill" → pick customer → the form's `[TOKEN]` placeholders
  (`<span class="fill">[CUSTOMER NAME]</span>` convention) are filled from
  that customer's record + `system_spec`; a "Prepared for" block is
  prepended; it opens in the in-browser editor.
- Installer / SAA / NMI / compliance tokens are deliberately left
  highlighted for the installer to complete by hand.
- Saving publishes the filled HTML to the customer
  (`document_publications.body_html`); they View it in their portal.
  It is a snapshot — the customer keeps exactly what was sent.
