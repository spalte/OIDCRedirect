FROM node:lts-alpine
ENV NODE_ENV=production
ENV LOGGED_IN_USER_SUB=0123456789

WORKDIR /app

COPY ["package.json", "package-lock.json*", "./"]

RUN npm install --production

COPY ["server.js", "./"]

CMD [ "node", "server.js" ]
