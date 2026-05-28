FROM node:22-alpine AS build

WORKDIR /app
ENV NEXT_TELEMETRY_DISABLED=1

COPY dashboard/package*.json ./
RUN npm ci

COPY dashboard/ ./
COPY docs/assets/mark.svg public/mark.svg
RUN npm run build

FROM node:22-alpine

WORKDIR /app

ENV NODE_ENV=production \
    NEXT_TELEMETRY_DISABLED=1 \
    HOSTNAME=0.0.0.0 \
    PORT=8090

COPY dashboard/package*.json ./
RUN npm ci --omit=dev

COPY --from=build /app/public ./public
COPY --from=build /app/.next/standalone ./
COPY --from=build /app/.next/static ./.next/static

EXPOSE 8090

CMD ["node", "server.js"]
