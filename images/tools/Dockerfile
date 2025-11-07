# Copyright IBM Corp. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0

# ---------------------------------------
#
# ---------------------------------------
ARG GO_VER
ARG UBUNTU_VER

FROM georgekyr/golang-pqcrypto:1.0 as golang
ADD . $GOPATH/src/github.com/hyperledger/fabric
WORKDIR $GOPATH/src/github.com/hyperledger/fabric

FROM golang as tools
ARG GO_TAGS
RUN make tools GO_TAGS=${GO_TAGS}

# ---------------------------------------
#
# ---------------------------------------
FROM georgekyr/golang-pqcrypto:1.0

RUN apt update && apt install -y \
	bash \
	git \
	jq \
	tzdata

RUN echo 'hosts: files dns' > /etc/nsswitch.conf

ENV FABRIC_CFG_PATH /etc/hyperledger/fabric
ENV LD_LIBRARY_PATH /usr/local/lib

COPY --from=tools /usr/local/go/src/crypto                            /usr/local/go/src/crypto
COPY --from=tools /go/src/github.com/hyperledger/fabric/build/bin     /usr/local/bin
COPY --from=tools /go/src/github.com/hyperledger/fabric/sampleconfig  ${FABRIC_CFG_PATH}

VOLUME /etc/hyperledger/fabric