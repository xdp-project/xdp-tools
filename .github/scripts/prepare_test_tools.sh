#!/bin/bash

set -e

echo ::group::Install bpftool
git clone --depth=1 https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git bpftool
sudo make install -C bpftool/tools/bpf/bpftool/ prefix=/usr
echo ::endgroup::


echo ::group::Install xdp-test-harness
sudo python3 -m pip install xdp_test_harness
echo ::endgroup::


echo ::group::Install virtme
git clone https://github.com/amluto/virtme
sudo python3 -m pip install ./virtme
echo ::endgroup::
