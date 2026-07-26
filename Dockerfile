# Multi-stage build - Builder
FROM node:22-alpine AS builder

WORKDIR /app

# Copy and install dependencies only
COPY package.json package-lock.json* ./
RUN npm ci --omit=dev --no-audit --no-fund

# Multi-stage build - Runtime
FROM node:22-alpine

# Install only necessary system packages
RUN apk add --no-cache ca-certificates

# Create non-root user for security
RUN addgroup -g 1000 app && adduser -D -u 1000 -G app app

WORKDIR /app

# Copy node_modules from builder
COPY --from=builder /app/node_modules ./node_modules

# Copy application code with proper ownership
COPY --chown=app:app . .

# Create data directory
RUN mkdir -p /data && chown -R app:app /data

# Switch to non-root user
USER app

ENV NODE_ENV=production
ENV DB_PATH=/data/solarsync.db

EXPOSE 3000

CMD ["sh", "-c", "node seed-if-empty.js && node server.js"]
