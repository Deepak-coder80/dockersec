FROM node:latest
ENV AWS_SECRET_KEY=abc123
RUN apt-get update
RUN apt-get install curl
RUN curl | bash
RUN sudo npm install
RUN pip install flask
ADD . /app
COPY package.json /app
WORKDIR /app
RUN apt-get install nc
EXPOSE 80
CMD ["node", "index.js"]
RUN chmod 777 /app
RUN wget https://example.com/script.sh
