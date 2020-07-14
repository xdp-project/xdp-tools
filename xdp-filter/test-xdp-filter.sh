XDP_LOADER=${XDP_LOADER:-./xdp-loader}
XDP_FILTER=${XDP_FILTER:-./xdp-filter}
ALL_TESTS="test_load test_ports_allow test_ports_deny test_ipv6_allow test_ipv6_deny test_ipv4_allow test_ipv4_deny"

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
    PID=$(start_background tcpdump -epni $NS "$filter")
    echo "Started listener as $PID"
    sleep 1
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
    [[ "$type" == "tcp" ]] && command="nc -w 1 -z $OUTSIDE_IP6 $port"
    [[ "$type" == "udp" ]] && command="echo test | nc -w 1 -u $OUTSIDE_IP6 $port"

    check_packet "$type dst port $port" "$command" $expect
}

test_ports_allow()
{
    local TEST_PORT=10000

    # default allow mode
    check_run $XDP_FILTER load $NS -v
    check_port tcp $TEST_PORT OK
    check_port udp $TEST_PORT OK
    check_run $XDP_FILTER port $TEST_PORT -v
    check_port tcp $TEST_PORT FAIL
    check_port tcp $[TEST_PORT+1] OK
    check_port udp $TEST_PORT FAIL
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
    check_run $XDP_FILTER load -p deny $NS -v
    check_port tcp $TEST_PORT FAIL
    check_port udp $TEST_PORT FAIL
    check_run $XDP_FILTER port $TEST_PORT -v
    check_port tcp $TEST_PORT OK
    check_port tcp $[TEST_PORT+1] FAIL
    check_port udp $TEST_PORT OK
    check_port udp $[TEST_PORT+1] FAIL
    check_run $XDP_FILTER port -r $TEST_PORT -v
    check_port tcp $TEST_PORT FAIL
    check_port udp $TEST_PORT FAIL
    check_run $XDP_FILTER unload $NS -v
}

check_ping6()
{
    check_packet "dst $OUTSIDE_IP6" "$PING6 -c 1 $OUTSIDE_IP6" $1
}

test_ipv6_allow()
{
    check_ping6 OK
    check_run $XDP_FILTER load $NS -v
    check_run $XDP_FILTER ip $OUTSIDE_IP6
    check_ping6 FAIL
    check_run $XDP_FILTER ip -r $OUTSIDE_IP6
    check_ping6 OK
    check_run $XDP_FILTER ip -m src $INSIDE_IP6
    check_ping6 FAIL
    check_run $XDP_FILTER ip -m src -r $INSIDE_IP6
    check_ping6 OK
    check_run $XDP_FILTER unload $NS -v
}

test_ipv6_deny()
{
    check_ping6 OK
    check_run $XDP_FILTER load -p deny $NS -v
    check_run $XDP_FILTER ip $OUTSIDE_IP6
    check_ping6 OK
    check_run $XDP_FILTER ip -r $OUTSIDE_IP6
    check_ping6 FAIL
    check_run $XDP_FILTER ip -m src $INSIDE_IP6
    check_ping6 OK
    check_run $XDP_FILTER ip -m src -r $INSIDE_IP6
    check_ping6 FAIL
    check_run $XDP_FILTER unload $NS -v
}

check_ping4()
{
    check_packet "dst $OUTSIDE_IP4" "ping -c 1 $OUTSIDE_IP4" $1
}

test_ipv4_allow()
{
    check_ping4 OK
    check_run $XDP_FILTER load $NS -v
    check_run $XDP_FILTER ip $OUTSIDE_IP4
    check_ping4 FAIL
    check_run $XDP_FILTER ip -r $OUTSIDE_IP4
    check_ping4 OK
    check_run $XDP_FILTER ip -m src $INSIDE_IP4
    check_ping4 FAIL
    check_run $XDP_FILTER ip -m src -r $INSIDE_IP4
    check_ping4 OK
    check_run $XDP_FILTER unload $NS -v
}

test_ipv4_deny()
{
    check_ping4 OK
    check_run $XDP_FILTER load -p deny $NS -v
    check_run $XDP_FILTER ip $OUTSIDE_IP4
    check_ping4 OK
    check_run $XDP_FILTER ip -r $OUTSIDE_IP4
    check_ping4 FAIL
    check_run $XDP_FILTER ip -m src $INSIDE_IP4
    check_ping4 OK
    check_run $XDP_FILTER ip -m src -r $INSIDE_IP4
    check_ping4 FAIL
    check_run $XDP_FILTER unload $NS -v
}

cleanup_tests()
{
    $XDP_FILTER unload --all >/dev/null 2>&1
    $XDP_LOADER unload $NS --all >/dev/null 2>&1
}
