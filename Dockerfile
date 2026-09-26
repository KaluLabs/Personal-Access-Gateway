FROM node:22-bookworm-slim
WORKDIR /app
COPY package.json ./
COPY bin ./bin
COPY src ./src
COPY public ./public
COPY config ./config
COPY docker-entrypoint.sh ./docker-entrypoint.sh
RUN chmod +x ./bin/pag.js ./docker-entrypoint.sh && mkdir -p /data
ENV PAG_DATA_DIR=/data PAG_HOST=0.0.0.0 PAG_PORT=8787
VOLUME ["/data"]
EXPOSE 8787
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 CMD node -e "fetch('http://127.0.0.1:8787/health').then(r=>{if(!r.ok)process.exit(1)}).catch(()=>process.exit(1))"
ENTRYPOINT ["./docker-entrypoint.sh"]
