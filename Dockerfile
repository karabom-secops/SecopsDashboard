# Built and run by Coolify (Dockerfile build pack). Coolify's Traefik proxy
# terminates TLS and forwards to port 3000; server.js already trusts one proxy
# hop and strips the /secops base path, so no nginx is needed in front.
FROM node:24-alpine

# psql, so db/migrate-*.sql can be run from the Coolify terminal:
#   psql -h "$PG_HOST" -U "$PG_USER" -d "$PG_DATABASE" -f db/migrate-x.sql
RUN apk add --no-cache postgresql-client

WORKDIR /app

COPY package*.json ./
RUN npm ci --omit=dev

COPY . .

# data/ holds weeks.json, metrics.json and the report archive (data/reports).
# Mount a Coolify persistent volume at /app/data or they are lost on redeploy.
RUN mkdir -p /app/data/reports && chown -R node:node /app/data

USER node

ENV NODE_ENV=production \
    PORT=3000

EXPOSE 3000

# login.html is static and served before auth, so it answers without a session.
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:'+(process.env.PORT||3000)+'/login.html').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"

CMD ["node", "server.js"]
