# Copyright IBM Corp. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

ARG GO_VER
ARG UBUNTU_VER

FROM ubuntu:${UBUNTU_VER} as base

RUN apt update && apt install -y \
        libssl-dev \
        python3-pytest \
        python3-pytest-xdist \
        zip \
        libxslt1-dev \
        doxygen \
        graphviz \
        python3-yaml \
        valgrind \
    && rm -rf /var/lib/apt/lists/*

# Ubuntu-style user creation
RUN groupadd -g 500 chaincode && \
    useradd -u 500 -g chaincode -d /home/chaincode -m -s /bin/bash chaincode

USER chaincode