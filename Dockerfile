FROM node:22-alpine

WORKDIR /app

RUN corepack enable && corepack prepare pnpm@9.15.5 --activate

COPY package.json pnpm-lock.yaml ./
RUN pnpm install --frozen-lockfile --prod

COPY server.js README.md .env.example ./
COPY public ./public

ENV NODE_ENV=production
ENV DATA_FILE=/var/lib/gravis/gravis.json

RUN mkdir -p /var/lib/gravis && chown -R node:node /app /var/lib/gravis
USER node

EXPOSE 5000
CMD ["node", "server.js"]
