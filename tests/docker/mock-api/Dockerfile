FROM node:18-alpine
WORKDIR /app
RUN npm init -y && npm install express
COPY server.js .
CMD ["node", "server.js"]
