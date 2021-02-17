#!/bin/bash

set -e

echo travis_fold:start:install_bpftool
echo "Install bpftool"
git clone --depth=1 https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git bpftool
sudo make install -C bpftool/tools/bpf/bpftool/ prefix=/usr
echo travis_fold:end:install_bpftool


echo travis_fold:start:install_xdp_test_harness
echo "Install xdp-test-harness"
sudo python3 -m pip install xdp_test_harness
echo travis_fold:end:install_xdp_test_harness


echo travis_fold:start:install_virtme
echo "Install virtme"
git clone https://github.com/amluto/virtme
sudo python3 -m pip install ./virtme
echo travis_fold:end:install_virtme


if [[ $KERNEL_VERSION == "LATEST" ]]; then
    echo travis_fold:start:install_pahole
    echo "Install pahole"
    # In the repo there is only version 1.15 and we need newer.
    git clone https://git.kernel.org/pub/scm/devel/pahole/pahole.git
    mkdir pahole/build
    cd pahole/build
    cmake -D__LIB=lib ..
    sudo make install
    sudo ldconfig /usr/local/lib
    echo travis_fold:end:install_pahole
fi
