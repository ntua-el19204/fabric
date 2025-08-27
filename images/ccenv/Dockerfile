# Copyright IBM Corp. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

ARG GO_VER
ARG UBUNTU_VER
FROM golang:${GO_VER}
RUN apt-get update && apt-get install -y \
	binutils-gold \
	g++ \
	gcc \
	git \
	libc6-dev \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /chaincode/output /chaincode/input
RUN groupadd -g 500 chaincode && \
    useradd -u 500 -g chaincode -d /home/chaincode -m -s /bin/bash chaincode
RUN chown -R chaincode:chaincode /chaincode
USER chaincode