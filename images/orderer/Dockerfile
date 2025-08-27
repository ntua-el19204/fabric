# Use your Docker Hub image instead of local base image
FROM georgekyr/golang-pqcrypto:latest as golang

# Force Go to use local installation, not download toolchains
ENV GOTOOLCHAIN=local
ENV GOROOT=/usr/local/go
ENV GOPATH=/go
ENV PATH=/usr/local/go/bin:$PATH
ENV LD_LIBRARY_PATH=/usr/local/lib
ENV PKG_CONFIG_PATH=/liboqs-go/.config

ADD . $GOPATH/src/github.com/hyperledger/fabric
WORKDIR $GOPATH/src/github.com/hyperledger/fabric

# Verify Go is using your crypto package
RUN go env GOROOT
RUN ls -la /usr/local/go/src/crypto/pqc/dilithium/dilithium5/
RUN go list crypto/pqc/dilithium/dilithium5

ARG GO_TAGS
ARG FABRIC_VER
RUN make orderer GO_TAGS=${GO_TAGS} FABRIC_VER=${FABRIC_VER}

FROM ubuntu:24.04

ARG FABRIC_VER
RUN echo 'hosts: files dns' > /etc/nsswitch.conf

ENV FABRIC_CFG_PATH /etc/hyperledger/fabric
ENV FABRIC_VER ${FABRIC_VER}
ENV LD_LIBRARY_PATH /usr/local/lib

COPY --from=golang /usr/local/lib /usr/local/lib
COPY --from=golang /usr/local/go/src/crypto /usr/local/go/src/crypto
COPY --from=golang /go/src/github.com/hyperledger/fabric/build/bin/orderer /usr/local/bin
COPY --from=golang /go/src/github.com/hyperledger/fabric/sampleconfig/msp ${FABRIC_CFG_PATH}/msp
COPY --from=golang /go/src/github.com/hyperledger/fabric/sampleconfig/orderer.yaml ${FABRIC_CFG_PATH}
COPY --from=golang /go/src/github.com/hyperledger/fabric/sampleconfig/configtx.yaml ${FABRIC_CFG_PATH}

VOLUME /etc/hyperledger/fabric
VOLUME /var/hyperledger
EXPOSE 7050
CMD ["orderer", "start"]