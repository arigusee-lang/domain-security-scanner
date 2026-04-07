FROM node:20-slim AS build
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci
COPY . .
RUN npm run build

FROM node:20-slim
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev
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
