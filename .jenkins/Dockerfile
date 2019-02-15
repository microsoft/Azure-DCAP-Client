# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.
ARG ubuntu_version=16.04
FROM ubuntu:${ubuntu_version}

ARG UNAME
ARG GNAME
ARG UID
ARG GID

RUN apt-get update \
    && apt-get install -y \
    build-essential \
    curl \
    debhelper \
    libcurl4-openssl-dev \
    libssl-dev \
    pkg-config \
    wget && \
    groupadd --gid ${GID} ${GNAME} && \
    useradd --create-home --uid ${UID} --gid ${GID} --shell /bin/bash ${UNAME}
