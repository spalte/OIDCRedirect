FROM node:lts-alpine
ENV NODE_ENV=production

EXPOSE 80
WORKDIR /app

COPY ["package.json", "package-lock.json*", "./"]
RUN npm install --production

COPY ["server.js", "./"]

CMD [ "node", "server.js" ]
