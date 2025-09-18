#!/bin/bash

set -e


echo ::group::Install xdp-test-harness
sudo python3 -m pip install xdp_test_harness
echo ::endgroup::
