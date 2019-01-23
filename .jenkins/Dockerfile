FROM ubuntu:16.04

ARG UNAME
ARG GNAME
ARG UID
ARG GID

RUN groupadd --gid ${GID} ${GNAME} && \
    useradd --create-home --uid ${UID} --gid ${GID} --shell /bin/bash ${UNAME}

RUN apt-get update \
    && apt-get install -y \
    build-essential \
    curl \
    debhelper \
    libcurl4-openssl-dev \
    libssl-dev \
    pkg-config \
    wget
