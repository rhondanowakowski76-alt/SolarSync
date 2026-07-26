# ---- deps stage: install with npm, then discard npm itself ----
FROM node:22-alpine AS deps
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev --no-audit --no-fund

# ---- runtime stage: no npm/npx/corepack shipped, no Perl, no glibc ----
FROM node:22-alpine
RUN apk add --no-cache ca-certificates \
    && rm -rf /usr/local/lib/node_modules/npm /usr/local/bin/npm /usr/local/bin/npx \
              /usr/local/lib/node_modules/corepack /usr/local/bin/corepack \
    && addgroup -S app && adduser -S app -G app

WORKDIR /app
COPY --from=deps /app/node_modules ./node_modules
COPY . .

RUN mkdir -p /data && chown -R app:app /app /data
ENV DB_PATH=/data/solarsync.db
ENV NODE_ENV=production

USER app
EXPOSE 3000

CMD ["sh", "-c", "node seed-if-empty.js && node server.js"]


