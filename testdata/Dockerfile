FROM node:latest
ENV AWS_SECRET_KEY=abc123
RUN apt-get install curl
RUN curl | bash
RUN npm install
ADD . /app
COPY package.json /app
WORKDIR /app
EXPOSE 80
CMD ["node", "index.js"]