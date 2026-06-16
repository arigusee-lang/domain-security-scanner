FROM node:20-slim AS build
WORKDIR /app
COPY package.json package-lock.json ./
# Skip Chromium download in build stage — final image installs it.
ENV PUPPETEER_SKIP_DOWNLOAD=true
RUN npm ci --legacy-peer-deps
COPY . .
RUN npm run build

FROM node:20-slim
WORKDIR /app

# System libs required by Chromium for headless PDF rendering (Puppeteer).
# Without these the bundled Chromium fails to launch in a slim image.
RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates \
      fonts-liberation \
      libasound2 \
      libatk-bridge2.0-0 \
      libatk1.0-0 \
      libc6 \
      libcairo2 \
      libcups2 \
      libdbus-1-3 \
      libdrm2 \
      libexpat1 \
      libfontconfig1 \
      libgbm1 \
      libglib2.0-0 \
      libgtk-3-0 \
      libnspr4 \
      libnss3 \
      libpango-1.0-0 \
      libx11-6 \
      libx11-xcb1 \
      libxcb1 \
      libxcomposite1 \
      libxdamage1 \
      libxext6 \
      libxfixes3 \
      libxkbcommon0 \
      libxrandr2 \
      wget \
      xdg-utils \
    && rm -rf /var/lib/apt/lists/*

COPY package.json package-lock.json ./
RUN npm ci --omit=dev --legacy-peer-deps
# tsx needed at runtime to run TS server
RUN npm i tsx
COPY --from=build /app/dist ./dist
COPY server ./server
COPY src/lib ./src/lib
ENV NODE_ENV=production
ENV PORT=8080
ENV DB_DIR=/data
EXPOSE 8080
# Create data directory for SQLite
RUN mkdir -p /data
CMD ["npx", "tsx", "server/index.ts"]
