#docker build . -t xdp-synproxy:0.1
#docker run -it -h xdp-synproxy --network=host --privileged xdp-synproxy:0.1

FROM ubuntu:latest

RUN apt-get update && \
    apt-get install -y libelf1 \
                       iptables \
                       iproute2

COPY bpftool /usr/local/bin
COPY install-rules.sh /
COPY uninstall-rules.sh /
COPY xdp_synproxy /usr/local/bin

#ENTRYPOINT ["/usr/local/bin/xdp_synproxy", "--iface", "ens192", "--file", "/usr/local/bin/xdp_synproxy_kern.o", "--mss4", "1460", "--mss6", "1440", "--wscale", "7", "--ttl", "254", "--ports", "80,8080"]


