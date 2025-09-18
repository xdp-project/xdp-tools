#!/bin/bash

ENVVARS="KERNEL_VERSION DID_UNSHARE CLANG"

touch ENVVARS
for v in $ENVVARS; do
    val=$(eval echo '$'$v)
    echo "$v=$val" >> ENVVARS
done

touch TEST_OUTPUT
tail -f TEST_OUTPUT &

sudo virtme-ng --run kernel --exec .github/scripts/run_tests.sh --rw --memory 2G

kill %1

exit "$(cat TEST_RESULT)"
