XDP_LOADER=${XDP_LOADER:-./xdp-loader}
XDP_FILTER=${XDP_FILTER:-./xdp-filter}
ALL_TESTS="test_load test_print test_output_remove test_ports_allow test_ports_deny test_ipv6_allow test_ipv6_deny test_ipv4_allow test_ipv4_deny test_ether_allow test_ether_deny"

try_feat()
{
    local output

    feat=$1
    prog=$2
    shift 2

    output=$($XDP_FILTER load $NS --features $feat "$@" -v 2>&1)
    ret=$?
    if [ "$ret" -ne "0" ]; then
        return $ret
    fi
    echo "$output"
    regex="Found prog '$prog'"
    if ! [[ $output =~ $regex ]]; then
        echo
        echo "Couldn't find '$regex' in output for feat $feat" >&2
        return 1
    fi
    check_run $XDP_FILTER unload $NS -v
}

test_load()
{

    declare -a FEATS=(tcp udp ipv4 ipv6 ethernet all)
    declare -a PROGS_D=(xdpfilt_dny_tcp.o xdpfilt_dny_udp.o xdpfilt_dny_ip.o xdpfilt_dny_ip.o xdpfilt_dny_eth.o xdpfilt_dny_all.o)
    declare -a PROGS_A=(xdpfilt_alw_tcp.o xdpfilt_alw_udp.o xdpfilt_alw_ip.o xdpfilt_alw_ip.o xdpfilt_alw_eth.o xdpfilt_alw_all.o)
    local len=${#FEATS[@]}

    for (( i=0; i<$len; i++ )); do
        if ! try_feat ${FEATS[$i]} ${PROGS_A[$i]}; then
            return 1
        fi
        if ! try_feat ${FEATS[$i]} ${PROGS_A[$i]} --mode skb; then
            return 1
        fi
        if ! try_feat ${FEATS[$i]} ${PROGS_D[$i]} --policy deny; then
            return 1
        fi
        if ! try_feat ${FEATS[$i]} ${PROGS_D[$i]} --policy deny --mode skb; then
            return 1
        fi
    done

    if [ -d /sys/fs/bpf/xdp-filter ]; then
        die "/sys/fs/bpf/xdp-filter still exists!"
    fi
}

check_packet()
{
    local filter="$1"
    local command="$2"
    local expect="$3"
    echo "Checking command '$command' filter '$filter'"
    PID=$(start_background tcpdump --immediate-mode -epni $NS "$filter")
    echo "Started listener as $PID"
    ns_exec bash -c "$command"
    sleep 1
    output=$(stop_background $PID)
    echo "$output"

    if [[ "$expect" == "OK" ]]; then
        regex="[1-9] packets? captured"
    else
        regex="0 packets captured"
    fi

    if [[ "$output" =~ $regex ]]; then
        echo "Packet check $expect SUCCESS"
        return 0
    else
        echo "Packet check $expect FAILURE"
        exit 1
    fi
}

check_port()
{
    local type=$1
    local port=$2
    local expect=$3
    echo "$type port $port $expect"
    [[ "$type" == "tcp" ]] && command="echo test | socat - TCP6:[$OUTSIDE_IP6]:$port,connect-timeout=1"
    [[ "$type" == "udp" ]] && command="echo test | socat - UDP6:[$OUTSIDE_IP6]:$port"

    check_packet "$type dst port $port" "$command" $expect
}

test_ports_allow()
{
    local TEST_PORT=10000

    # default allow mode
    check_run $XDP_FILTER load -f udp,tcp $NS -v
    check_port tcp $TEST_PORT OK
    check_port udp $TEST_PORT OK
    check_run $XDP_FILTER port $TEST_PORT -v
    check_port tcp $TEST_PORT NOTOK
    check_port tcp $[TEST_PORT+1] OK
    check_port udp $TEST_PORT NOTOK
    check_port udp $[TEST_PORT+1] OK
    check_run $XDP_FILTER port -r $TEST_PORT -v
    check_port tcp $TEST_PORT OK
    check_port udp $TEST_PORT OK
    check_run $XDP_FILTER unload $NS -v
}

test_ports_deny()
{
    local TEST_PORT=10000
    # default deny mode
    check_run $XDP_FILTER load -p deny -f udp,tcp $NS -v
    check_port tcp $TEST_PORT NOTOK
    check_port udp $TEST_PORT NOTOK
    check_run $XDP_FILTER port $TEST_PORT -v
    check_port tcp $TEST_PORT OK
    check_port tcp $[TEST_PORT+1] NOTOK
    check_port udp $TEST_PORT OK
    check_port udp $[TEST_PORT+1] NOTOK
    check_run $XDP_FILTER port -r $TEST_PORT -v
    check_port tcp $TEST_PORT NOTOK
    check_port udp $TEST_PORT NOTOK
    check_run $XDP_FILTER unload $NS -v
}

check_ping6()
{
    check_packet "dst $OUTSIDE_IP6" "$PING6 -c 1 $OUTSIDE_IP6" $1
}

test_ipv6_allow()
{
    check_ping6 OK
    check_run $XDP_FILTER load -f ipv6 $NS -v
    check_run $XDP_FILTER ip $OUTSIDE_IP6
    check_ping6 NOTOK
    check_run $XDP_FILTER ip -r $OUTSIDE_IP6
    check_ping6 OK
    check_run $XDP_FILTER ip -m src $INSIDE_IP6
    check_ping6 NOTOK
    check_run $XDP_FILTER ip -m src -r $INSIDE_IP6
    check_ping6 OK
    check_run $XDP_FILTER unload $NS -v
}

test_ipv6_deny()
{
    check_ping6 OK
    check_run $XDP_FILTER load -p deny -f ipv6 $NS -v
    check_run $XDP_FILTER ip $OUTSIDE_IP6
    check_ping6 OK
    check_run $XDP_FILTER ip -r $OUTSIDE_IP6
    check_ping6 NOTOK
    check_run $XDP_FILTER ip -m src $INSIDE_IP6
    check_ping6 OK
    check_run $XDP_FILTER ip -m src -r $INSIDE_IP6
    check_ping6 NOTOK
    check_run $XDP_FILTER unload $NS -v
}

check_ping4()
{
    check_packet "dst $OUTSIDE_IP4" "ping -c 1 $OUTSIDE_IP4" $1
}

test_ipv4_allow()
{
    check_ping4 OK
    check_run $XDP_FILTER load -f ipv4 $NS -v
    check_run $XDP_FILTER ip $OUTSIDE_IP4
    check_ping4 NOTOK
    check_run $XDP_FILTER ip -r $OUTSIDE_IP4
    check_ping4 OK
    check_run $XDP_FILTER ip -m src $INSIDE_IP4
    check_ping4 NOTOK
    check_run $XDP_FILTER ip -m src -r $INSIDE_IP4
    check_ping4 OK
    check_run $XDP_FILTER unload $NS -v
}

test_ipv4_deny()
{
    check_ping4 OK
    check_run $XDP_FILTER load -p deny -f ipv4 $NS -v
    check_run $XDP_FILTER ip $OUTSIDE_IP4
    check_ping4 OK
    check_run $XDP_FILTER ip -r $OUTSIDE_IP4
    check_ping4 NOTOK
    check_run $XDP_FILTER ip -m src $INSIDE_IP4
    check_ping4 OK
    check_run $XDP_FILTER ip -m src -r $INSIDE_IP4
    check_ping4 NOTOK
    check_run $XDP_FILTER unload $NS -v
}

test_ether_allow()
{
    check_ping6 OK
    check_run $XDP_FILTER load -f ethernet $NS -v
    check_run $XDP_FILTER ether $OUTSIDE_MAC
    check_ping6 NOTOK
    check_run $XDP_FILTER ether -r $OUTSIDE_MAC
    check_ping6 OK
    check_run $XDP_FILTER ether -m src $INSIDE_MAC
    check_ping6 NOTOK
    check_run $XDP_FILTER ether -m src -r $INSIDE_MAC
    check_ping6 OK
    check_run $XDP_FILTER unload $NS -v
}

test_ether_deny()
{
    check_ping6 OK
    check_run $XDP_FILTER load -p deny -f ethernet $NS -v
    check_run $XDP_FILTER ether $OUTSIDE_MAC
    check_ping6 OK
    check_run $XDP_FILTER ether -r $OUTSIDE_MAC
    check_ping6 NOTOK
    check_run $XDP_FILTER ether -m src $INSIDE_MAC
    check_ping6 OK
    check_run $XDP_FILTER ether -m src -r $INSIDE_MAC
    check_ping6 NOTOK
    check_run $XDP_FILTER unload $NS -v
}

check_status()
{
    local match
    local output
    match="$1"
    output=$($XDP_FILTER status)

    if echo "$output" | grep -q $match; then
        echo "Output check for $match SUCCESS"
        return 0
    else
        echo "Output check for $match FAILURE"
        echo "Output: $output"
        exit 1
    fi
}

check_status_no_match()
{
    local match
    local output
    match="$1"
    output=$($XDP_FILTER status)

    if echo "$output" | grep -q $match; then
        echo "Output check for no $match FAILURE"
        echo "Output: $output"
        exit 1
    else
        echo "Output check for no $match SUCCESS"
        return 0
    fi
}

test_print()
{
    check_run $XDP_FILTER load $NS -v
    check_run $XDP_FILTER ether aa:bb:cc:dd:ee:ff
    check_status "aa:bb:cc:dd:ee:ff"
    check_run $XDP_FILTER ip 1.2.3.4
    check_status "1.2.3.4"
    check_run $XDP_FILTER ip aa::bb
    check_status "aa::bb"
    check_run $XDP_FILTER port 100
    check_status "100.*dst,tcp,udp"
    check_run $XDP_FILTER unload $NS -v
}

check_port_removal_from_all()
{
    local command_options=$1
    local expected_output=$2

    local TEST_PORT=54321

    check_run $XDP_FILTER port $TEST_PORT -p tcp,udp -m src,dst
    check_status "$TEST_PORT.*src,dst,tcp,udp"

    check_run $XDP_FILTER port $TEST_PORT $command_options -r
    if [[ -z "$expected_output" ]]; then
        check_status_no_match "$TEST_PORT"
    else
        check_status "$TEST_PORT.*$expected_output"
    fi
}

test_output_remove()
{
    check_run $XDP_FILTER load $NS -v

    # Remove only one mode/proto.
    check_port_removal_from_all "-m src" "dst,tcp,udp"
    check_port_removal_from_all "-m dst" "src,tcp,udp"
    check_port_removal_from_all "-p udp" "src,dst,tcp"
    check_port_removal_from_all "-p tcp" "src,dst,udp"

    # Remove one from each.
    check_port_removal_from_all "-m src -p udp" "dst,tcp"
    check_port_removal_from_all "-m src -p tcp" "dst,udp"
    check_port_removal_from_all "-m dst -p udp" "src,tcp"
    check_port_removal_from_all "-m dst -p tcp" "src,udp"

    # Remove everything.
    check_port_removal_from_all "" ""
    check_port_removal_from_all "-m src,dst" ""
    check_port_removal_from_all "-p tcp,udp" ""
    check_port_removal_from_all "-m src,dst -p tcp,udp" ""


    check_run $XDP_FILTER unload $NS -v
}

get_python()
{
    if [[ -z "${PYTHON:-}" ]]; then
        local -a possible=(python3 python)
        local -a available

        local found=0
        for i in "${possible[@]}"; do
                PYTHON=$(which $i)
                if [[ $? -eq 0 ]]; then
                        found=1
                        break
                fi
        done
        if [[ found -eq 0 ]]; then
                return 1
        fi
    fi

    $PYTHON -c "import xdp_test_harness" &> /dev/null
    if [[ $? -ne 0 ]]; then
        # Libraries are not installed.
        return 1
    fi

    echo "$PYTHON"
}

run_python_test()
{
    local module="$1"
    local module_path
    local python

    module_path="$(realpath --relative-to=. "$TOOL_TESTS_DIR" | sed "s/\//./g")"
    if [[ $? -ne 0 ]] || [[ $module_path == "." ]]; then
        return "$SKIPPED_TEST"
    fi

    python="$(get_python)"
    if [[ $? -ne 0 ]]; then
        return "$SKIPPED_TEST"
    fi

    $python -m xdp_test_harness.runner client "$module_path"."$module"
    if [[ $? -ne 0 ]]; then
        return 1
    fi

    return 0
}

test_python_basic()
{
    run_python_test test_basic
}

test_python_slow()
{
    run_python_test test_slow
}

cleanup_tests()
{
    $XDP_FILTER unload $NS >/dev/null 2>&1
    $XDP_LOADER unload $NS --all >/dev/null 2>&1
}
