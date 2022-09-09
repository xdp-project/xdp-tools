FROM golang:1.18.5 as builder

ENV TOOLS_VERSION=1.2.6
ENV TOOLS_RELEASE=1

# Packages to install via APT for building.
ENV BUILD_DEPS=" \
    clang llvm libelf-dev libpcap-dev gcc-multilib build-essential m4 \
    unzip \
    wget \
    swig \
    checkinstall \
    "

ENV XDPTOOLS_SRC=./xdp-tools-1.2.6
ENV XDPTOOLS_GO=/go/src/xdptools
ENV BUILD_OUTPUT=/target

# install dependencies required for bulding libxdp lib
RUN apt-get update && apt -y install \
    ${BUILD_DEPS} && \
    rm -rf /var/lib/apt/lists/*

# Download libxdp source
RUN wget -O xdp-tools.tar.gz "https://github.com/xdp-project/xdp-tools/releases/download/v${TOOLS_VERSION}/xdp-tools-1.2.6.tar.gz" \
    && tar xvfz xdp-tools.tar.gz \
    && rm -f xdp-tools.tar.gz

COPY ./ ${XDPTOOLS_GO}/

# build libxdp
RUN  mkdir $BUILD_OUTPUT; \
     env >> $BUILD_OUTPUT/env.txt; \
     apt-get update -qq; \
     cd $XDPTOOLS_SRC; \
     ./configure; \
     make libxdp 2>&1 | tee -a $BUILD_OUTPUT/build_log.txt; \
     checkinstall -y -d0 --pkgname libxdp --pkgversion ${TOOLS_VERSION} --backup=no --strip=no --stripso=no --install=no --pakdir $BUILD_OUTPUT  2>&1 | tee -a $BUILD_OUTPUT/build_log.txt;

RUN  apt-get update && apt -y install $BUILD_OUTPUT/libxdp_${TOOLS_VERSION}-${TOOLS_RELEASE}_amd64.deb libbpf-dev
RUN ldconfig -v

ENV CGO_LDFLAGS=-lxdp

RUN cd ${XDPTOOLS_GO}/; go build
