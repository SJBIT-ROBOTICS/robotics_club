FROM node:20-alpine

WORKDIR /app

# Copy application files (Zero external dependencies needed!)
COPY server.js ./
COPY index.html ./
COPY public ./public
COPY package.json ./

ENV NODE_ENV=production
ENV PORT=8080

EXPOSE 8080

CMD ["node", "server.js"]
