#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Script to setup and manage tests for xdp-tools.
# Based on the test-env script from xdp-tutorial.
#
# Author:   Toke Høiland-Jørgensen (toke@redhat.com)
# Date:     26 May 2020
# Copyright (c) 2020 Red Hat

set -o nounset
umask 077

TEST_PROG_DIR="${TEST_PROG_DIR:-$(dirname "${BASH_SOURCE[0]}")}"
SETUP_SCRIPT="$TEST_PROG_DIR/setup-netns-env.sh"
TEST_CONFIG="$TEST_PROG_DIR/test_config.sh"
IP6_SUBNET=fc42:dead:cafe # must have exactly three :-separated elements
IP6_PREFIX_SIZE=64 # Size of assigned prefixes
IP6_FULL_PREFIX_SIZE=48 # Size of IP6_SUBNET
IP4_SUBNET=10.11
IP4_PREFIX_SIZE=24 # Size of assigned prefixes
IP4_FULL_PREFIX_SIZE=16 # Size of IP4_SUBNET
GENERATED_NAME_PREFIX="xdptest"
ALL_TESTS=""
VERBOSE_TESTS=${V:-0}
NUM_NS=2

NEEDED_TOOLS="capinfos ethtool ip ping sed tc tcpdump timeout tshark nft socat"

if [ -f "$TEST_CONFIG" ]; then
    source "$TEST_CONFIG"
fi

if command -v ping6 >/dev/null 2>&1; then
    PING6=ping6
else
    PING6=ping
fi

# Odd return value for skipping, as only 0-255 is valid.
SKIPPED_TEST=249

# Global state variables that will be set by options etc below
STATEDIR=
CMD=
NS=
NS_NAMES=()

IP6_PREFIX=
IP4_PREFIX=
INSIDE_IP6=
INSIDE_IP4=
INSIDE_MAC=
OUTSIDE_IP6=
OUTSIDE_IP4=
OUTSIDE_MAC=
ALL_INSIDE_IP6=()
ALL_INSIDE_IP4=()

is_trace_attach_supported()
{
    if [[ -z "${TRACE_ATTACH_SUPPORT:-}" ]]; then
        [ -f "$STATEDIR/trace_attach_support" ] && \
            TRACE_ATTACH_SUPPORT=$(< "$STATEDIR/trace_attach_support")

        if [[ -z "${TRACE_ATTACH_SUPPORT:-}" ]]; then
            RESULT=$($XDP_LOADER load -v "$NS" "$TEST_PROG_DIR/xdp_pass.o" 2>&1)
            PID=$(start_background "$XDPDUMP -i $NS")
            RESULT=$(stop_background "$PID")
            if [[ "$RESULT" == *"The kernel does not support fentry function attach"* ]]; then
                TRACE_ATTACH_SUPPORT="false"
            else
                TRACE_ATTACH_SUPPORT="true"
            fi
            echo "$TRACE_ATTACH_SUPPORT" > "$STATEDIR/trace_attach_support"
            $XDP_LOADER unload "$NS" --all
        fi
    fi

    if [[ "$TRACE_ATTACH_SUPPORT" == "true" ]]; then
        return 0
    else
        return 1
    fi
}

is_multiprog_supported()
{
    if [[ -z "${MULTIPROG_SUPPORT:-}" ]]; then
        RESULT=$($XDP_LOADER load -v "$NS" "$TEST_PROG_DIR/xdp_pass.o" 2>&1)
        if [[ "$RESULT" == *"Compatibility check for dispatcher program failed"* ]]; then
            MULTIPROG_SUPPORT="false"
        else
            MULTIPROG_SUPPORT="true"
        fi
        $XDP_LOADER unload "$NS" --all
    fi

    if [[ "$MULTIPROG_SUPPORT" == "true" ]]; then
        return 0
    else
        return 1
    fi
}

is_progmap_supported()
{
    if [[ -z "${PROGMAP_SUPPORT:-}" ]]; then
        RESULT=$(timeout -s INT 1 $XDP_BENCH redirect-cpu "$NS" -c 0 -r drop -vv 2>&1)
        if [[ "$RESULT" == *"Create CPU entry failed: Cannot allocate memory"* ]]; then
            PROGMAP_SUPPORT="false"
        else
            PROGMAP_SUPPORT="true"
        fi
    fi

    if [[ "$PROGMAP_SUPPORT" == "true" ]]; then
        return 0
    else
        return 1
    fi
}

skip_if_missing_veth_rxq()
{
    if ! ethtool -l $NS >/dev/null 2>&1; then
        exit "$SKIPPED_TEST"
    fi
}

skip_if_missing_cpumap_attach()
{
    if ! $TEST_PROG_DIR/test-tool probe cpumap-prog; then
        exit "$SKIPPED_TEST"
    fi
}

skip_if_missing_xdp_load_bytes()
{
    if ! $TEST_PROG_DIR/test-tool probe xdp-load-bytes; then
        exit "$SKIPPED_TEST"
    fi
}

skip_if_missing_kernel_symbol()
{
    if ! grep -q "$1" /proc/kallsyms; then
        exit "$SKIPPED_TEST"
    fi
}

skip_if_legacy_fallback()
{
    if ! is_multiprog_supported; then
        exit "$SKIPPED_TEST"
    fi
}

skip_if_missing_trace_attach()
{
    if ! is_trace_attach_supported; then
        exit "$SKIPPED_TEST"
    fi
}

die()
{
    echo "$1" >&2
    exit 1
}

start_background()
{
    local TMP_FILE="${STATEDIR}/tmp_proc_$$_$RANDOM"
    setsid bash -c "$*" &> ${TMP_FILE} &
    local PID=$!
    sleep 2 # Wait to make sure the command is executed in the background

    mv "$TMP_FILE" "${STATEDIR}/proc/${PID}" >& /dev/null

    echo "$PID"
}

start_background_no_stderr()
{
    local TMP_FILE="${STATEDIR}/tmp_proc_$$_$RANDOM"
    setsid bash -c "$*" 1> ${TMP_FILE} 2>/dev/null &
    local PID=$!
    sleep 2 # Wait to make sure the command is executed in the background

    mv "$TMP_FILE" "${STATEDIR}/proc/${PID}" >& /dev/null

    echo "$PID"
}

start_background_ns_devnull()
{
    local TMP_FILE="${STATEDIR}/tmp_proc_$$_$RANDOM"
    setsid ip netns exec "$NS" env TESTENV_NAME="$NS" "$SETUP_SCRIPT" bash -c "$*" 1>/dev/null 2>${TMP_FILE} &
    local PID=$!
    sleep 2 # Wait to make sure the command is executed in the background

    mv "$TMP_FILE" "${STATEDIR}/proc/${PID}" >& /dev/null
    echo $PID
}

stop_background()
{
    local PID=$1

    local OUTPUT_FILE="${STATEDIR}/proc/${PID}"
    if kill -SIGINT "-$PID" 2>/dev/null; then
       sleep 2 # Wait to make sure the buffer is flushed after the shutdown
       kill -SIGTERM "-$PID" 2>/dev/null && sleep 1 # just in case SIGINT was not enough
    fi

    if [ -f "$OUTPUT_FILE" ]; then
        cat "$OUTPUT_FILE"
        rm "$OUTPUT_FILE" >& /dev/null
    fi
}

check_prereq()
{
    local max_locked_mem=$(ulimit -l)

    for t in $NEEDED_TOOLS; do
        command -v "$t" > /dev/null || die "Missing required tool: $t"
    done

    if [ "$EUID" -ne "0" ]; then
        die "This script needs root permissions to run."
    fi

    STATEDIR="$(mktemp -d --tmpdir=${TMPDIR:-/tmp} --suffix=.xdptest)"
    if [ $? -ne 0 ]; then
        die "Unable to create state dir in $TMPDIR"
    fi
    mkdir ${STATEDIR}/proc

    if [ "$max_locked_mem" != "unlimited" ]; then
	ulimit -l unlimited || die "Unable to set ulimit"
    fi

    mount -t bpf bpf /sys/fs/bpf/ || die "Unable to mount bpffs"
}

gen_nsname()
{
    local nsname

    while
        nsname=$(printf "%s-%04x" "$GENERATED_NAME_PREFIX" $RANDOM)
        [ -e "$STATEDIR/${nsname}.ns" ]
    do true; done

    touch "$STATEDIR/${nsname}.ns"
    echo $nsname
}

iface_macaddr()
{
    local iface="$1"
    ip -br link show dev "$iface" | awk '{print $3}'
}

set_sysctls()
{
    local iface="$1"
    local in_ns="${2:-}"
    local nscmd=

    [ -n "$in_ns" ] && nscmd="ip netns exec $in_ns"
    local sysctls_off_v6=(accept_dad
                       accept_ra
                       mldv1_unsolicited_report_interval
                       mldv2_unsolicited_report_interval)
    local sysctls_on=(forwarding)

    for s in ${sysctls_off_v6[*]}; do
        $nscmd sysctl -w net.ipv6.conf.$iface.${s}=0 >/dev/null
    done
    for s in ${sysctls_on[*]}; do
        $nscmd sysctl -w net.ipv6.conf.$iface.${s}=1 >/dev/null
        $nscmd sysctl -w net.ipv6.conf.all.${s}=1 >/dev/null
        $nscmd sysctl -w net.ipv4.conf.$iface.${s}=1 >/dev/null
        $nscmd sysctl -w net.ipv4.conf.all.${s}=1 >/dev/null
    done
}

init_ns()
{
    local nsname=$1
    local num=$2
    local peername="testl-ve-$num"

    IP6_PREFIX="${IP6_SUBNET}:${num}::"
    IP4_PREFIX="${IP4_SUBNET}.$((0x$num))."

    INSIDE_IP6="${IP6_PREFIX}2"
    INSIDE_IP4="${IP4_PREFIX}2"
    OUTSIDE_IP6="${IP6_PREFIX}1"
    OUTSIDE_IP4="${IP4_PREFIX}1"

    ip netns add "$nsname"
    ip link add dev "$nsname" type veth peer name "$peername"
    set_sysctls $nsname

    ethtool -K "$nsname" rxvlan off txvlan off gro on
    ethtool -K "$peername" rxvlan off txvlan off gro on

    OUTSIDE_MAC=$(iface_macaddr "$nsname")
    INSIDE_MAC=$(iface_macaddr "$peername")
    ip link set dev "$peername" netns "$nsname"
    ip link set dev "$nsname" up
    ip addr add dev "$nsname" "${OUTSIDE_IP6}/${IP6_PREFIX_SIZE}"

    ip -n "$nsname" link set dev "$peername" name veth0
    ip -n "$nsname" link set dev lo up
    ip -n "$nsname" link set dev veth0 up
    set_sysctls veth0 "$nsname"
    ip -n "$nsname" addr add dev veth0 "${INSIDE_IP6}/${IP6_PREFIX_SIZE}"

    # Prevent neighbour queries on the link
    ip neigh add "$INSIDE_IP6" lladdr "$INSIDE_MAC" dev "$nsname" nud permanent
    ip -n "$nsname" neigh add "$OUTSIDE_IP6" lladdr "$OUTSIDE_MAC" dev veth0 nud permanent

    ip addr add dev "$nsname" "${OUTSIDE_IP4}/${IP4_PREFIX_SIZE}"
    ip -n "$nsname" addr add dev veth0 "${INSIDE_IP4}/${IP4_PREFIX_SIZE}"
    ip neigh add "$INSIDE_IP4" lladdr "$INSIDE_MAC" dev "$nsname" nud permanent
    ip -n "$nsname" neigh add "$OUTSIDE_IP4" lladdr "$OUTSIDE_MAC" dev veth0 nud permanent

    # Add default routes inside the ns
    ip -n "$nsname" route add default via $OUTSIDE_IP4 dev veth0
    ip -n "$nsname" -6 route add default via $OUTSIDE_IP6 dev veth0

    ALL_INSIDE_IP4+=($INSIDE_IP4)
    ALL_INSIDE_IP6+=($INSIDE_IP6)
}

setup()
{
    local nsname

    set -o errexit

    check_prereq

    for i in $(seq $NUM_NS); do
        nsname=$(gen_nsname)
        init_ns $nsname $i
        NS_NAMES+=($nsname)
    done

    set +o errexit

    NS=$nsname
}

teardown_ns()
{
    local nsname=$1

    ip link del dev "$nsname"
    ip netns del "$nsname"
    [ -d "/sys/fs/bpf/$nsname" ] && rmdir "/sys/fs/bpf/$nsname" || true

}

teardown()
{
    for ns in "${NS_NAMES[@]}"; do
        teardown_ns $ns
    done

    for f in ${STATEDIR}/proc/*; do
        if [ -f "$f" ]; then
            local pid="${f/${STATEDIR}\/proc\//}"
            stop_background "$pid" &> /dev/null || true
        fi
    done

    rm -rf "$STATEDIR"
}

ns_exec()
{
    ip netns exec "$NS" env TESTENV_NAME="$NS" "$SETUP_SCRIPT" "$@"
}

is_func()
{
    type "$1" 2>/dev/null | grep -q 'is a function'
}

check_run()
{
    local ret

    "$@"
    ret=$?
    echo "Command '$@' exited with status $ret"
    echo ""
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
        echo "$output" | sed  's/^/          /'
        echo "          Test $testn exited with return code: $ret"
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

if [ "$EUID" -ne "0" ]; then
    if command -v sudo >/dev/null 2>&1; then
        exec sudo env V=${VERBOSE_TESTS} DEBUG_TESTENV=${DEBUG_TESTENV:-0} "$0" "$@"
    else
        die "Tests should be run as root"
    fi
else
    if [ "${DID_UNSHARE:-0}" -ne "1" ]; then
        echo "    Executing tests in separate net- and mount namespaces" >&2
        exec env DID_UNSHARE=1 unshare -n -m "$0" "$@"
    fi
fi

export XDPDUMP
export XDP_BENCH
export XDP_FILTER
export XDP_FORWARD
export XDP_LOADER
export XDP_MONITOR
export XDP_TRAFFICGEN

TEST_DEFINITIONS="${1:-}"
[ -f "$TEST_DEFINITIONS" ] || usage
source "$TEST_DEFINITIONS"

TOOL_TESTS_DIR="$(dirname "$TEST_DEFINITIONS")"

shift
trap teardown EXIT
setup

if [ "${DEBUG_TESTENV:-0}" -eq "1" ] && [ -n "$SHELL" ]; then
    echo "Entering interactive testenv debug - Ctrl-D to exit and resume test execution"
    $SHELL
fi

run_tests "$@"
