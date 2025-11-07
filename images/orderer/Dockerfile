#
# Copyright contributors to the Hyperledger Fabric project
#
# SPDX-License-Identifier: Apache-2.0
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
# 	  http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

# ---------------------------------------
#
# ---------------------------------------
ARG GO_VER
ARG UBUNTU_VER

FROM ubuntu:${UBUNTU_VER} as base
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
FROM golang as orderer
ARG GO_TAGS
ENV LD_LIBRARY_PATH /usr/local/lib
RUN make orderer GO_TAGS=${GO_TAGS}

FROM base
ENV FABRIC_CFG_PATH /etc/hyperledger/fabric

VOLUME /etc/hyperledger/fabric
VOLUME /var/hyperledger

ENV LD_LIBRARY_PATH /usr/local/lib

COPY --from=orderer /usr/local/lib                                                          /usr/local/lib
COPY --from=orderer /usr/local/go/src/crypto /usr/local/go/src/crypto
COPY --from=orderer /go/src/github.com/hyperledger/fabric/build/bin/orderer                 /usr/local/bin
COPY --from=orderer /go/src/github.com/hyperledger/fabric/sampleconfig/msp                  ${FABRIC_CFG_PATH}/msp
COPY --from=orderer /go/src/github.com/hyperledger/fabric/sampleconfig/orderer.yaml         ${FABRIC_CFG_PATH}
COPY --from=orderer /go/src/github.com/hyperledger/fabric/sampleconfig/configtx.yaml        ${FABRIC_CFG_PATH}

EXPOSE 7050
CMD ["orderer"]