FROM georgekyr/golang-pqcrypto:latest as golang

ENV LD_LIBRARY_PATH=/usr/local/lib
ENV PKG_CONFIG_PATH=/liboqs-go/.config
ENV GOROOT=/usr/local/go
ENV GOPATH=/go
ENV PATH=/usr/local/go/bin:$PATH
ENV GOTOOLCHAIN=local

ADD . $GOPATH/src/github.com/hyperledger/fabric
WORKDIR $GOPATH/src/github.com/hyperledger/fabric

ARG GO_TAGS
ARG FABRIC_VER
RUN make peer GO_TAGS=${GO_TAGS} FABRIC_VER=${FABRIC_VER}

FROM ubuntu:24.04

ARG FABRIC_VER

RUN echo 'hosts: files dns' > /etc/nsswitch.conf

ENV FABRIC_CFG_PATH /etc/hyperledger/fabric
ENV FABRIC_VER      ${FABRIC_VER}
ENV LD_LIBRARY_PATH /usr/local/lib

COPY --from=golang /usr/local/lib /usr/local/lib
COPY --from=golang /usr/local/go/src/crypto /usr/local/go/src/crypto
COPY --from=golang /go/src/github.com/hyperledger/fabric/build/bin/peer /usr/local/bin

VOLUME /etc/hyperledger/fabric
VOLUME /var/hyperledger

EXPOSE 7051

CMD ["peer", "node", "start"]