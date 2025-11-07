FROM golang:1.24.4

RUN apt-get -y update && \
    apt-get install -y \
    	astyle \
    	cmake \
    	gcc \
    	ninja-build \
    	libssl-dev \
    	python3-pytest \
    	python3-pytest-xdist \
    	unzip \
    	xsltproc \
    	doxygen \
    	graphviz \
    	python3-yaml \
    	valgrind

WORKDIR /
RUN git clone -b main https://github.com/open-quantum-safe/liboqs.git && \
    git clone https://github.com/open-quantum-safe/liboqs-go

WORKDIR /liboqs
RUN mkdir build

WORKDIR /liboqs/build
RUN cmake -GNinja .. -DBUILD_SHARED_LIBS=ON -DOQS_BUILD_ONLY_LIB=ON && \
    ninja && ninja install
    
ENV LD_LIBRARY_PATH=/usr/local/lib
ENV PKG_CONFIG_PATH=/liboqs-go/.config

WORKDIR /usr/local/go/src/
RUN rm -r crypto

RUN git clone https://github.com/ntua-el19204/PQCrypto.git temp && \
    mv temp/crypto . && \
    rm -rf temp

    	
	
