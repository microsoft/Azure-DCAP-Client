FROM ubuntu:16.04

ARG UNAME=jenkins
ARG GNAME=jenkins
ARG UID=1001
ARG GID=1001

RUN groupadd --gid ${GID} ${GNAME} && \
    useradd --create-home --uid ${UID} --gid ${GID} --shell /bin/bash ${UNAME}

RUN apt-get update \
    && apt-get install -y \
    build-essential \
    curl \
    debhelper \
    libcurl4-openssl-dev \
    libssl-dev \
    wget
