#!/bin/bash

set -e


echo ::group::Install xdp-test-harness
sudo python3 -m pip install xdp_test_harness
echo ::endgroup::


echo ::group::Install virtme
git clone https://github.com/amluto/virtme
sudo python3 -m pip install ./virtme
echo ::endgroup::
