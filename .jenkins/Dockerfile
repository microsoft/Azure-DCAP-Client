# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

ARG ubuntu_version=18.04

FROM oejenkinscidockerregistry.azurecr.io/oetools-full-${ubuntu_version}

ARG UNAME=jenkins

RUN apt-get purge az-dcap-client -y && \
    apt-get update && \
    apt-get install sudo libcurl4-openssl-dev wget -y && \
    echo "${UNAME} ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers
