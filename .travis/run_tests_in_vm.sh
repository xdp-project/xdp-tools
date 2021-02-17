#!/bin/bash

sudo virtme-run --kdir kernel --script-exec .travis/run_tests.sh --pwd --rw --mods=auto --qemu-opts -m 512M
exit "$(cat RESULT)"