# coordinator — public API the browser calls directly (CORS is origin:true).
# Uses node:sqlite (built into Node 22) so there is NO native module to compile.
# Build context is the REPO ROOT.
#   docker build -f services/coordinator/Dockerfile .
FROM node:22-bookworm-slim
RUN corepack enable && corepack prepare pnpm@10.6.1 --activate
WORKDIR /app
COPY . .
RUN pnpm install --frozen-lockfile

# HOST=:: binds the IPv6 dual stack so Railway's public proxy can reach it.
# COORDINATOR_PORT is mapped from Railway's injected $PORT at launch (below).
# CTN_DB_PATH defaults to /app/.data/coordinator.sqlite (ephemeral) — set it to a
# mounted volume path in Railway if you want the demo graph to survive redeploys.
ENV HOST=:: \
    CTN_ENV=demo
EXPOSE 4200
WORKDIR /app/services/coordinator
# Map Railway's $PORT onto the port the service reads. exec so signals reach node.
CMD ["sh", "-c", "COORDINATOR_PORT=\"${PORT:-4200}\" exec pnpm start"]
