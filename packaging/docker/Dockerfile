FROM debian:13 AS builder

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    build-essential \
    clang \
    llvm \
    libelf-dev \
    libpcap-dev \
    libbpf-dev \
    pkg-config \
    git \
    wget \
    m4 \
    zlib1g-dev \
    libcap-dev \
    bpftool \
    && rm -rf /var/lib/apt/lists/*

COPY . /opt/xdp-tools
WORKDIR /opt/xdp-tools

RUN ./configure && make && make install

FROM debian:13-slim AS runtime

RUN apt-get update && apt-get install -y \
    libelf1 \
    libpcap0.8 \
    libbpf1 \
    libcap2 \
    bpftool \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /usr/local /usr/local

ENV PATH="/usr/local/bin:/usr/local/sbin:$PATH"

ENTRYPOINT []
CMD ["xdp-loader"]
