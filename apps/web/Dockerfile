# web — the Next.js app (the deck rides along at /deck.html). Public on Railway.
# NEXT_PUBLIC_COORDINATOR_URL is inlined at BUILD time, so it must be the
# coordinator's PUBLIC URL and known before this image is built. Railway passes
# service variables as build args, so declaring the ARG picks it up.
# Build context is the REPO ROOT.
#   docker build -f apps/web/Dockerfile --build-arg NEXT_PUBLIC_COORDINATOR_URL=https://... .
FROM node:22-bookworm-slim
RUN corepack enable && corepack prepare pnpm@10.6.1 --activate
WORKDIR /app
COPY . .
RUN pnpm install --frozen-lockfile

ARG NEXT_PUBLIC_COORDINATOR_URL
ENV NEXT_PUBLIC_COORDINATOR_URL=$NEXT_PUBLIC_COORDINATOR_URL
RUN pnpm --filter @ctn/web build

ENV NODE_ENV=production
EXPOSE 3000
WORKDIR /app/apps/web
# Next listens on Railway's injected $PORT (falls back to 3000 locally).
CMD ["sh", "-c", "exec pnpm exec next start -p \"${PORT:-3000}\""]
