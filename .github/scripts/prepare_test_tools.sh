#!/bin/bash

set -e


echo ::group::Install xdp-test-harness
sudo python3 -m pip install xdp_test_harness
echo ::endgroup::


echo ::group::Install virtme
git clone https://github.com/amluto/virtme
sudo python3 -m pip install ./virtme
echo ::endgroup::


if [[ $KERNEL_VERSION == "LATEST" ]]; then
    echo ::group::Install pahole
    # In the repo there is only version 1.15 and we need newer.
    git clone https://git.kernel.org/pub/scm/devel/pahole/pahole.git
    mkdir pahole/build
    cd pahole/build
    cmake -D__LIB=lib ..
    sudo make install
    sudo ldconfig /usr/local/lib
    echo ::endgroup::
fi
