FROM       node:10-stretch
RUN        sudo apt-get update
RUN        sudo apt-get install openssl
WORKDIR    /app
COPY       . .
ENTRYPOINT [ "npm", "t" ]
