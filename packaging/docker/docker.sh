#!/usr/bin/bash
docker run -it --rm \
    --privileged \
    --network=host \
    --cap-add=ALL \
    --volume /lib/modules:/lib/modules:ro \
    --volume /sys:/sys \
    --volume $(pwd):/work \
    littlejo/xdp-tools:0.2.0 \
    bash
