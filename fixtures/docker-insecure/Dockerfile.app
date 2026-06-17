# Fixture: intentionally insecure Dockerfile to exercise checkDockerDeep.

# 1. Unpinned base image — :latest (HIGH) and implicit Docker Hub namespace (LOW)
FROM node:latest

# 10. Secret passed via build ARG (bakes into image history)
ARG NPM_TOKEN
ARG DB_PASSWORD
ARG SERVICE_API_KEY

# 2. Remote pipe-to-shell — unverified RCE at build time
RUN curl -sSL https://get.example.com/install.sh | sh
RUN wget -qO- https://install.example.com/setup | bash

# 3. sudo install + chmod 777
RUN apt-get install -y sudo
RUN sudo apt-get update
RUN chmod -R 777 /app

# 6. apt-get install -y without --no-install-recommends
RUN apt-get install -y curl wget

# 5. ADD of a local archive (auto-extract) and COPY whole context
ADD release-bundle.tar.gz /opt/app/
COPY . .

# 9. USER root as an explicit user directive
USER root

# 9b. --no-sandbox flag
CMD ["chromium", "--no-sandbox", "--headless"]
