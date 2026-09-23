FROM node:22-alpine AS build

WORKDIR /app
ARG VITE_MISP_DELIVERY_DISABLED=false
ARG VITE_ACTIT_DEMO_MODE=false
ENV VITE_MISP_DELIVERY_DISABLED=$VITE_MISP_DELIVERY_DISABLED
ENV VITE_ACTIT_DEMO_MODE=$VITE_ACTIT_DEMO_MODE
COPY package.json package-lock.json ./
RUN npm ci --ignore-scripts
COPY . .
RUN npm run lint && VITE_MISP_DELIVERY_DISABLED=false VITE_ACTIT_DEMO_MODE=false npm test && npm run build

FROM nginxinc/nginx-unprivileged:1.27-alpine

COPY --chmod=0644 nginx.conf /etc/nginx/conf.d/default.conf
RUN test "$(stat -c '%a' /etc/nginx/conf.d/default.conf)" = "644" \
    && test -r /etc/nginx/conf.d/default.conf
COPY --from=build /app/dist /usr/share/nginx/html

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=3s --retries=3 \
  CMD wget -qO- http://127.0.0.1:8080/healthz >/dev/null || exit 1
