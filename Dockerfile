FROM node:22-bookworm-slim

# CA certs for outbound HTTPS (Stripe, DigitalOcean Spaces, etc.)
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY package.json ./
RUN npm install --omit=dev --no-audit --no-fund

COPY . .

# Local data dir. NOTE: on DigitalOcean App Platform the container filesystem is
# ephemeral and is wiped on every deploy/restart. For persistent data use a
# DigitalOcean Managed Postgres database and point the app at it via env vars
# (e.g. DATABASE_URL) instead of relying on this path.
RUN mkdir -p /data
ENV DB_PATH=/data/solarsync.db
ENV NODE_ENV=production

EXPOSE 3000

# Seed only if the database doesn't exist yet, then start.
CMD ["sh", "-c", "node seed-if-empty.js && node server.js"]
