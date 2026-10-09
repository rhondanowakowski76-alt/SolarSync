# ---- deps stage: install with npm, then discard npm itself ----
FROM node:22-alpine AS deps
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev --no-audit --no-fund

# ---- build stage: precompile the app's JSX (no packages needed; see build.js) ----
FROM node:22-alpine AS build
WORKDIR /app
COPY build.js ./
COPY public/index.html ./public/index.html
COPY public/vendor/babel-standalone.min.js ./public/vendor/babel-standalone.min.js
RUN node build.js

# ---- runtime stage: no npm/npx/corepack shipped, no Perl, no glibc ----
FROM node:22-alpine
RUN apk add --no-cache ca-certificates \
    && rm -rf /usr/local/lib/node_modules/npm /usr/local/bin/npm /usr/local/bin/npx \
              /usr/local/lib/node_modules/corepack /usr/local/bin/corepack \
    && addgroup -S app && adduser -S app -G app

WORKDIR /app
COPY --from=deps /app/node_modules ./node_modules
COPY . .
COPY --from=build /app/dist ./dist

RUN mkdir -p /app/data/pg && chown -R app:app /app
ENV NODE_ENV=production

USER app
EXPOSE 3000

CMD ["sh", "-c", "node seed-if-empty.js && node server.js"]


