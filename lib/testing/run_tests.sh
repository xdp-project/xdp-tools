#!/bin/bash

TEST_PROG_DIR="${TEST_PROG_DIR:-$(dirname "${BASH_SOURCE[0]}")}"
TESTS_DIR="${TESTS_DIR:-$TEST_PROG_DIR/tests}"
TEST_RUNNER="$TEST_PROG_DIR/test_runner.sh"

echo "Running all tests from $TESTS_DIR"
for f in "$TESTS_DIR"/*.sh; do
    "$TEST_RUNNER" "$f"
done
