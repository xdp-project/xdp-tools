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
SETUP_SCRIPT="$TEST_PROG_DIR/setup-netns-env.sh"
TEST_CONFIG="$TEST_PROG_DIR/test_config.sh"
IP6_SUBNET=fc42:dead:cafe # must have exactly three :-separated elements
IP6_PREFIX_SIZE=64 # Size of assigned prefixes
IP6_FULL_PREFIX_SIZE=48 # Size of IP6_SUBNET
IP4_SUBNET=10.11
IP4_PREFIX_SIZE=24 # Size of assigned prefixes
IP4_FULL_PREFIX_SIZE=16 # Size of IP4_SUBNET
VLAN_IDS=(1 2)
GENERATED_NAME_PREFIX="xdptest"
ALL_TESTS=""
VERBOSE_TESTS=${V:-0}

NEEDED_TOOLS="capinfos ethtool ip ping sed tc tcpdump timeout nc tshark"
MAX_NAMELEN=15

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
GENERATE_NEW=0
CLEANUP_FUNC=
STATEDIR=
STATEFILE=
CMD=
NS=
LEGACY_IP=1
USE_VLAN=0
RUN_ON_INNER=0

# State variables that are written to and read from statefile
STATEVARS=(IP6_PREFIX IP4_PREFIX
           INSIDE_IP6 INSIDE_IP4 INSIDE_MAC
           OUTSIDE_IP6 OUTSIDE_IP4 OUTSIDE_MAC
           ENABLE_IPV4 ENABLE_VLAN)
IP6_PREFIX=
IP4_PREFIX=
INSIDE_IP6=
INSIDE_IP4=
INSIDE_MAC=
OUTSIDE_IP6=
OUTSIDE_IP4=
OUTSIDE_MAC=
ENABLE_IPV4=0
ENABLE_VLAN=0

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
    get_nsname && ensure_nsname "$NS"

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
}

get_nsname()
{
    local GENERATE=${1:-1}

    if [ -z "$NS" ]; then
        [ -f "$STATEDIR/current" ] && NS=$(< "$STATEDIR/current")

        if [ "$GENERATE" -eq "1" ] && [ -z "$NS" ] || [ "$GENERATE_NEW" -eq "1" ]; then
            NS="$GENERATED_NAME_PREFIX"
            while [ -e "$STATEDIR/${NS}.state" ]; do
                NS=$(printf "%s-%04x" "$GENERATED_NAME_PREFIX" $RANDOM)
            done
        fi
    fi

    if [ "${#NS}" -gt "$MAX_NAMELEN" ]; then
        die "Environment name '$NS' is too long (max $MAX_NAMELEN)"
    fi

    STATEFILE="$STATEDIR/${NS}.state"
}

ensure_nsname()
{
    [ -z "$NS" ] && die "No environment selected; use --name to select one or 'setup' to create one"
    [ -e "$STATEFILE" ] || die "Environment for $NS doesn't seem to exist"

    echo "$NS" > "$STATEDIR/current"

    read_statefile
}

get_num()
{
    local num=1
    if [ -f "$STATEDIR/highest_num" ]; then
        num=$(( 1 + $(< "$STATEDIR/highest_num" )))
    fi

    echo $num > "$STATEDIR/highest_num"
    printf "%x" $num
}

write_statefile()
{
    [ -z "$STATEFILE" ] && return 1
    echo > "$STATEFILE"
    for var in "${STATEVARS[@]}"; do
        echo "${var}='$(eval echo '$'$var)'" >> "$STATEFILE"
    done
}

read_statefile()
{
    local value
    for var in "${STATEVARS[@]}"; do
        value=$(source "$STATEFILE"; eval echo '$'$var)
        eval "$var=\"$value\""
    done
}

cleanup_setup()
{
    echo "Error during setup, removing partially-configured environment '$NS'" >&2
    set +o errexit
    ip netns del "$NS" 2>/dev/null
    ip link del dev "$NS" 2>/dev/null
    rm -f "$STATEFILE"
}

cleanup_teardown()
{
    echo "Warning: Errors during teardown, partial environment may be left" >&2
}


cleanup()
{
    [ -n "$CLEANUP_FUNC" ] && $CLEANUP_FUNC

    local statefiles=("$STATEDIR"/*.state)

    if [ "${#statefiles[*]}" -eq 1 ] && [ ! -e "${statefiles[0]}" ]; then
        rm -f "${STATEDIR}/highest_num" "${STATEDIR}/current" \
           "${STATEDIR}/trace_attach_support"
        rmdir "$STATEDIR"
    fi
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
    local sysctls=(accept_dad
                   accept_ra
                   mldv1_unsolicited_report_interval
                   mldv2_unsolicited_report_interval)

    for s in ${sysctls[*]}; do
        $nscmd sysctl -w net.ipv6.conf.$iface.${s}=0 >/dev/null
    done
}

get_vlan_prefix()
{
    # Split the IPv6 prefix, and add the VLAN ID to the upper byte of the fourth
    # element in the prefix. This will break if the global prefix config doesn't
    # have exactly three elements in it.
    local prefix="$1"
    local vid="$2"
    (IFS=:; set -- $prefix; printf "%s:%s:%s:%x::" "$1" "$2" "$3" $(($4 + $vid * 4096)))
}

setup()
{
    get_nsname 1

    [ -e "$STATEFILE" ] && die "Environment for '$NS' already exists"

    local NUM=$(get_num "$NS")
    local PEERNAME="testl-ve-$NUM"
    [ -z "$IP6_PREFIX" ] && IP6_PREFIX="${IP6_SUBNET}:${NUM}::"
    [ -z "$IP4_PREFIX" ] && IP4_PREFIX="${IP4_SUBNET}.$((0x$NUM))."

    INSIDE_IP6="${IP6_PREFIX}2"
    INSIDE_IP4="${IP4_PREFIX}2"
    OUTSIDE_IP6="${IP6_PREFIX}1"
    OUTSIDE_IP4="${IP4_PREFIX}1"

    CLEANUP_FUNC=cleanup_setup

    if ! mount | grep -q /sys/fs/bpf; then
        mount -t bpf bpf /sys/fs/bpf/
    fi

    ip netns add "$NS"
    ip link add dev "$NS" type veth peer name "$PEERNAME"
    OUTSIDE_MAC=$(iface_macaddr "$NS")
    INSIDE_MAC=$(iface_macaddr "$PEERNAME")
    set_sysctls $NS

    ethtool -K "$NS" rxvlan off txvlan off
    ethtool -K "$PEERNAME" rxvlan off txvlan off
    ip link set dev "$PEERNAME" netns "$NS"
    ip link set dev "$NS" up
    ip addr add dev "$NS" "${OUTSIDE_IP6}/${IP6_PREFIX_SIZE}"

    ip -n "$NS" link set dev "$PEERNAME" name veth0
    ip -n "$NS" link set dev lo up
    ip -n "$NS" link set dev veth0 up
    set_sysctls veth0 "$NS"
    ip -n "$NS" addr add dev veth0 "${INSIDE_IP6}/${IP6_PREFIX_SIZE}"

    # Prevent neighbour queries on the link
    ip neigh add "$INSIDE_IP6" lladdr "$INSIDE_MAC" dev "$NS" nud permanent
    ip -n "$NS" neigh add "$OUTSIDE_IP6" lladdr "$OUTSIDE_MAC" dev veth0 nud permanent

    # Add route for whole test subnet, to make it easier to communicate between
    # namespaces
    ip -n "$NS" route add "${IP6_SUBNET}::/$IP6_FULL_PREFIX_SIZE" via "$OUTSIDE_IP6" dev veth0

    if [ "$LEGACY_IP" -eq "1" ]; then
        ip addr add dev "$NS" "${OUTSIDE_IP4}/${IP4_PREFIX_SIZE}"
        ip -n "$NS" addr add dev veth0 "${INSIDE_IP4}/${IP4_PREFIX_SIZE}"
        ip neigh add "$INSIDE_IP4" lladdr "$INSIDE_MAC" dev "$NS" nud permanent
        ip -n "$NS" neigh add "$OUTSIDE_IP4" lladdr "$OUTSIDE_MAC" dev veth0 nud permanent
        ip -n "$NS" route add "${IP4_SUBNET}/${IP4_FULL_PREFIX_SIZE}" via "$OUTSIDE_IP4" dev veth0
        ENABLE_IPV4=1
    else
        ENABLE_IPV4=0
    fi

    if [ "$USE_VLAN" -eq "1" ]; then
        ENABLE_VLAN=1
        for vid in "${VLAN_IDS[@]}"; do
            local vlpx="$(get_vlan_prefix "$IP6_PREFIX" "$vid")"
            local inside_ip="${vlpx}2"
            local outside_ip="${vlpx}1"
            ip link add dev "${NS}.$vid" link "$NS" type vlan id "$vid"
            ip link set dev "${NS}.$vid" up
            ip addr add dev "${NS}.$vid" "${outside_ip}/${IP6_PREFIX_SIZE}"
            ip neigh add "$inside_ip" lladdr "$INSIDE_MAC" dev "${NS}.$vid" nud permanent
            set_sysctls "${NS}/$vid"

            ip -n "$NS" link add dev "veth0.$vid" link "veth0" type vlan id "$vid"
            ip -n "$NS" link set dev "veth0.$vid" up
            ip -n "$NS" addr add dev "veth0.$vid" "${inside_ip}/${IP6_PREFIX_SIZE}"
            ip -n "$NS" neigh add "$outside_ip" lladdr "$OUTSIDE_MAC" dev "veth0.$vid" nud permanent
            set_sysctls "veth0/$vid" "$NS"
        done
    else
        ENABLE_VLAN=0
    fi

    write_statefile

    CLEANUP_FUNC=

    echo "$NS" > "$STATEDIR/current"
}

teardown()
{
    get_nsname && ensure_nsname "$NS"

    CLEANUP_FUNC=cleanup_teardown

    ip link del dev "$NS"
    ip netns del "$NS"
    rm -f "$STATEFILE"
    [ -d "/sys/fs/bpf/$NS" ] && rmdir "/sys/fs/bpf/$NS" || true

    if [ -f "$STATEDIR/current" ]; then
        local CUR=$(< "$STATEDIR/current" )
        [[ "$CUR" == "$NS" ]] && rm -f "$STATEDIR/current"
    fi

    for f in ${STATEDIR}/proc/*; do
        if [ -f "$f" ]; then
            local pid="${f/${STATEDIR}\/proc\//}"
            stop_background "$pid" &> /dev/null || true
        fi
    done

    rm -rf "$STATEDIR"

    CLEANUP_FUNC=
}

ns_exec()
{
    get_nsname && ensure_nsname "$NS"

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
    setup || return 1

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
        exec sudo env V=${VERBOSE_TESTS} "$0" "$@"
    else
        die "Tests should be run as root"
    fi
fi

export XDP_FILTER
export XDP_LOADER
export XDPDUMP

TEST_DEFINITIONS="${1:-}"
[ -f "$TEST_DEFINITIONS" ] || usage
source "$TEST_DEFINITIONS"

TOOL_TESTS_DIR="$(dirname "$TEST_DEFINITIONS")"

shift
trap teardown EXIT
check_prereq
run_tests "$@"
