FROM openjdk:8
LABEL maintainer="SAMATE, NIST"
WORKDIR /sard
RUN apt-get update && apt-get install -y --no-install-recommends make maven
COPY . .
