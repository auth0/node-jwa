FROM       node:10-stretch as base
WORKDIR    /app
COPY       . .
RUN        npm ci

# Make keys with: docker build --target genkeys -t node-jwa:keys .
FROM       node:10-stretch as genkeys
WORKDIR    /app
COPY       --from=base /app .
RUN        apt-get update
RUN        apt-get install openssl
RUN        ["mkdir", "-p", "test/fixtures"]
ENTRYPOINT ["npm", "run", "test:keys:gen"]

# Run tests with: docker build --target test -t node-jwa:test .
FROM       node:10-stretch as test
WORKDIR    /app
COPY       --from=base /app .
ENTRYPOINT [ "npm", "t" ]
