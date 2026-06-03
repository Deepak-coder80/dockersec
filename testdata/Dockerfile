FROM node:latest
ENV AWS_SECRET_KEY=abc123
RUN apt-get install curl
ADD . /app
COPY package.json /app
WORKDIR /app
RUN npm install
EXPOSE 3000
CMD ["node", "index.js"]
