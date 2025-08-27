#
# Copyright contributors to the Hyperledger Fabric project
#
# SPDX-License-Identifier: Apache-2.0
#

###############################################################################
# Build image - Use your PQ crypto image
###############################################################################

FROM georgekyr/golang-pqcrypto:latest as builder

ARG FABRIC_VER
ARG GO_TAGS

# Set PQ crypto environment
ENV GOTOOLCHAIN=local
ENV LD_LIBRARY_PATH=/usr/local/lib
ENV PKG_CONFIG_PATH=/liboqs-go/.config
ENV GOROOT=/usr/local/go
ENV GOPATH=/go
ENV PATH=/usr/local/go/bin:$PATH

# Copy Fabric source
ADD . $GOPATH/src/github.com/hyperledger/fabric
WORKDIR $GOPATH/src/github.com/hyperledger/fabric

# Build tools with your PQ crypto
RUN make tools GO_TAGS=${GO_TAGS} FABRIC_VER=${FABRIC_VER}

###############################################################################
# Runtime image - Use fixed Ubuntu version
###############################################################################

FROM ubuntu:24.04

ARG TARGETARCH
ARG TARGETOS
ARG FABRIC_VER
ARG GO_VER

RUN apt update && apt install -y \
    bash \
    curl \
    jq \
    tzdata

# Install Go in runtime (for tools that might need it)
RUN curl -sL https://go.dev/dl/go${GO_VER}.${TARGETOS}-${TARGETARCH}.tar.gz | tar zxvf - -C /usr/local
ENV PATH="/usr/local/go/bin:$PATH"

# set up nsswitch.conf for Go's "netgo" implementation
RUN echo 'hosts: files dns' > /etc/nsswitch.conf

ENV FABRIC_CFG_PATH /etc/hyperledger/fabric
ENV FABRIC_VER      ${FABRIC_VER}
ENV LD_LIBRARY_PATH /usr/local/lib

# Copy PQ crypto and built tools
COPY --from=builder /usr/local/lib /usr/local/lib
COPY --from=builder /usr/local/go/src/crypto /usr/local/go/src/crypto
COPY --from=builder /go/src/github.com/hyperledger/fabric/sampleconfig ${FABRIC_CFG_PATH}
COPY --from=builder /go/src/github.com/hyperledger/fabric/build/bin /usr/local/bin

VOLUME /etc/hyperledger/fabric
VOLUME /var/hyperledger