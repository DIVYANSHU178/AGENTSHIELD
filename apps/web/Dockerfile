# =============================================================================
# AgentShield Frontend Production Dockerfile (Phase 18 Containerization)
# Multi-stage build: minimal, non-root, zero-secret, Nginx static runtime.
# =============================================================================

# -----------------------------------------------------------------------------
# Stage 1: Static Application Builder
# -----------------------------------------------------------------------------
FROM node:20-alpine AS builder

WORKDIR /app

# Copy dependency manifests
COPY package.json package-lock.json ./

# Install exact locked dependencies
RUN npm ci

# Copy source code and build configuration
COPY . .

# Build production bundle (transpiles TypeScript, compiles Tailwind, bundles with Vite)
RUN npm run build

# -----------------------------------------------------------------------------
# Stage 2: Hardened Nginx Runtime
# -----------------------------------------------------------------------------
FROM nginx:1.27-alpine-slim AS runtime

# Remove default configuration and assets
RUN rm -rf /etc/nginx/conf.d/* /usr/share/nginx/html/*

# Copy built static assets from builder stage
COPY --from=builder /app/dist /usr/share/nginx/html

# Copy hardened, non-root reverse proxy configuration
COPY nginx.conf /etc/nginx/conf.d/default.conf

# Setup writeable paths and ownership for unprivileged nginx user (UID 101)
RUN touch /var/run/nginx.pid \
    && chown -R nginx:nginx /var/run/nginx.pid /var/cache/nginx /var/log/nginx /usr/share/nginx/html /etc/nginx/conf.d

# Drop all privileges to unprivileged nginx user
USER nginx

# Expose unprivileged non-root listening port
EXPOSE 8080

# Healthcheck testing HTTP response on port 8080
HEALTHCHECK --interval=15s --timeout=5s --start-period=5s --retries=3 \
    CMD wget -q -O /dev/null http://127.0.0.1:8080/ || exit 1

# Start Nginx in foreground
CMD ["nginx", "-g", "daemon off;"]
