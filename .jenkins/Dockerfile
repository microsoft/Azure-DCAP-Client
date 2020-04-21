# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

ARG ubuntu_version=18.04

FROM ubuntu:${ubuntu_version}

ARG UNAME=jenkins

COPY ./ /oe

RUN cd /oe/scripts/ansible && \
    ./install-ansible.sh && \
    ansible localhost --playbook-dir=/oe/scripts/ansible -m import_role -a "name=linux/docker tasks_from=ci-setup.yml" -vvv && \
    ./remove-ansible.sh && \
    cd / && \
    rm -rf /oe && \
    apt-get purge az-dcap-client -y && \
    apt-get update && \
    apt-get install sudo libcurl4-openssl-dev wget -y && \
    echo "${UNAME} ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers
