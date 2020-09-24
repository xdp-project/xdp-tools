#!/bin/bash

TEST_PROG_DIR="${TEST_PROG_DIR:-$(dirname "${BASH_SOURCE[0]}")}"
TESTS_DIR="${TESTS_DIR:-$TEST_PROG_DIR/tests}"
TEST_RUNNER="$TEST_PROG_DIR/test_runner.sh"

RET=0

echo "Running all tests from $TESTS_DIR"
for f in "$TESTS_DIR"/*/test-*.sh; do
    if [[ ! -f "$f" ]]; then
        echo "No tests found!"
        exit 1
    fi

    "$TEST_RUNNER" "$f" || RET=1
done

exit $RET
