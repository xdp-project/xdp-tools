#!/bin/bash

touch TEST_OUTPUT
tail -f TEST_OUTPUT &

sudo virtme-run --arch $KERNEL_ARCH --kdir kernel --script-exec .github/scripts/run_tests.sh --pwd --rw --mods=auto --memory 2G

kill %1

exit "$(cat TEST_RESULT)"
