FROM       node:10-stretch
RUN        sudo apt-get update
RUN        sudo apt-get install openssl
WORKDIR    /app
COPY       . .
RUN        npm ci
ENTRYPOINT [ "npm", "t" ]
