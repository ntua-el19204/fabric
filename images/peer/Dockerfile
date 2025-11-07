# Copyright IBM Corp. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0

# ---------------------------------------
#
# ---------------------------------------
ARG GO_VER
ARG UBUNTU_VER

FROM ubuntu:${UBUNTU_VER} as peer-base
RUN apt-get -y update && \
    apt-get install -y \
        tzdata \
        libssl-dev \
        python3-pytest \
        python3-pytest-xdist \
        zip \
        libxslt1-dev \
        doxygen \
        graphviz \
        python3-yaml \
        valgrind
# set up nsswitch.conf for Go's "netgo" implementation
# - https://github.com/golang/go/blob/go1.9.1/src/net/conf.go#L194-L275
# - docker run --rm debian:stretch grep '^hosts:' /etc/nsswitch.conf
RUN echo 'hosts: files dns' > /etc/nsswitch.conf

# ---------------------------------------
#
# ---------------------------------------
FROM georgekyr/golang-pqcrypto:1.0 as golang
ADD . $GOPATH/src/github.com/hyperledger/fabric
WORKDIR $GOPATH/src/github.com/hyperledger/fabric

# ---------------------------------------
#
# ---------------------------------------
FROM golang as peer
ARG GO_TAGS
RUN make peer GO_TAGS=${GO_TAGS}
RUN make ccaasbuilder

# ---------------------------------------
#
# ---------------------------------------
FROM peer-base
ENV FABRIC_CFG_PATH /etc/hyperledger/fabric
VOLUME /etc/hyperledger/fabric
VOLUME /var/hyperledger
COPY --from=golang /usr/local/lib/* /usr/local/lib/

COPY --from=golang /usr/local/lib/liboqs.so* /usr/local/lib/
RUN printf "/usr/local/lib\n" > /etc/ld.so.conf.d/usrlocal.conf && ldconfig

COPY --from=peer /usr/local/go/src/crypto                                                       /usr/local/go/src/crypto
COPY --from=peer /go/src/github.com/hyperledger/fabric/build/bin/peer                           /usr/local/bin
COPY --from=peer /go/src/github.com/hyperledger/fabric/sampleconfig/msp                         ${FABRIC_CFG_PATH}/msp
COPY --from=peer /go/src/github.com/hyperledger/fabric/sampleconfig/core.yaml                   ${FABRIC_CFG_PATH}/core.yaml
COPY --from=peer /go/src/github.com/hyperledger/fabric/release/linux-amd64/builders/ccaas/bin   /opt/hyperledger/ccaas_builder/bin

EXPOSE 7051
CMD ["peer","node","start"]

# To run it use: docker build   -f images/peer/Dockerfile   --build-arg UBUNTU_VER=24.04   --build-arg GO_TAGS=""   -t peer .
# from the root directory of the project