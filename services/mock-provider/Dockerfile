# mock-provider — the stand-in upstream provider. Internal-only on Railway.
# Build context is the REPO ROOT (pnpm workspace needs the root lockfile).
#   docker build -f services/mock-provider/Dockerfile .
FROM node:22-bookworm-slim
RUN corepack enable && corepack prepare pnpm@10.6.1 --activate
WORKDIR /app
COPY . .
RUN pnpm install --frozen-lockfile

# HOST=:: so Railway's IPv6 private network can reach it; fixed internal port.
ENV HOST=:: \
    MOCK_PROVIDER_PORT=4300
EXPOSE 4300
WORKDIR /app/services/mock-provider
CMD ["pnpm", "start"]
