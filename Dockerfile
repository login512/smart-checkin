FROM node:22-alpine

WORKDIR /app

COPY package.json package-lock.json* ./
RUN npm install --omit=dev && npm cache clean --force

COPY . .

RUN mkdir -p /app/data && chown -R node:node /app/data
USER node

ENV NODE_ENV=production
ENV PORT=3512
ENV DATA_DIR=/app/data

EXPOSE 3512

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD wget -qO- http://127.0.0.1:3512/healthz || exit 1

CMD ["node", "--no-warnings", "src/server.js"]
