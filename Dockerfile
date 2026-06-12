FROM node:22-bookworm-slim

# build tools for better-sqlite3 native module (falls back to prebuilt when available)
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 make g++ ca-certificates && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY package.json ./
RUN npm install --omit=dev --no-audit --no-fund

COPY . .

# data volume mount point (Fly mounts solarsync_data here)
RUN mkdir -p /data
ENV DB_PATH=/data/solarsync.db
ENV NODE_ENV=production

EXPOSE 3000
# Seed only if the database doesn't exist yet, then start.
CMD ["sh", "-c", "node seed-if-empty.js && node server.js"]
