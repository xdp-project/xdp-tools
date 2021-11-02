#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Script to setup and manage tests for xdp-tools.
# Based on the test-env script from xdp-tutorial.
#
# Author:   Toke Høiland-Jørgensen (toke@redhat.com)
# Date:     26 May 2020
# Copyright (c) 2020 Red Hat

set -o errexit
set -o nounset
umask 077

TEST_PROG_DIR="${TEST_PROG_DIR:-$(dirname "${BASH_SOURCE[0]}")}"
ALL_TESTS=""
VERBOSE_TESTS=${V:-0}

TMPDIR=$(mktemp --tmpdir -d config.XXXXXX)
trap 'status=$?; rm -rf $TMPDIR; exit $status' EXIT HUP INT QUIT TERM


# Odd return value for skipping, as only 0-255 is valid.
SKIPPED_TEST=249

is_func()
{
    type "$1" 2>/dev/null | grep -q 'is a function'
}

check_run()
{
    local ret

    [ "$VERBOSE_TESTS" -eq "1" ] && echo "$@"
    "$@"
    ret=$?
    if [ "$ret" -ne "0" ]; then
        exit $ret
    fi
}

exec_test()
{
    local testn="$1"
    local output
    local ret

    printf "     %-30s" "[$testn]"
    if ! is_func "$testn"; then
        echo "INVALID"
        return 1
    fi

    output=$($testn 2>&1)
    ret=$?
    if [ "$ret" -eq "0" ]; then
        echo "PASS"
    elif [ "$ret" -eq "$SKIPPED_TEST" ]; then
        echo "SKIPPED"
        ret=0
    else
        echo "FAIL"
    fi
    if [ "$ret" -ne "0" ] || [ "$VERBOSE_TESTS" -eq "1" ]; then
        echo "$output" | sed 's/^/\t/'
    fi
    return $ret
}

run_tests()
{
    local TESTS="$*"
    local ret=0
    [ -z "$TESTS" ] && TESTS="$ALL_TESTS"

    echo "    Running tests from $TEST_DEFINITIONS"

    for testn in $TESTS; do
        exec_test $testn || ret=1
        if is_func cleanup_tests; then
            cleanup_tests || true
        fi
    done

    return $ret
}

usage()
{
    echo "Usage: $0 <test_definition_file> [test names]" >&2
    exit 1
}

TEST_DEFINITIONS="${1:-}"
[ -f "$TEST_DEFINITIONS" ] || usage
source "$TEST_DEFINITIONS"

shift
run_tests "$@"
