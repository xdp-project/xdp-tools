#!/bin/bash

touch TEST_OUTPUT
tail -f TEST_OUTPUT &

sudo virtme-run --kdir kernel --script-exec .github/scripts/run_tests.sh --pwd --rw --mods=auto --qemu-opts -cpu qemu64 -machine accel=tcg -m 2G

kill %1

exit "$(cat TEST_RESULT)"