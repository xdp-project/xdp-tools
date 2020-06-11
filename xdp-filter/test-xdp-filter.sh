XDP_FILTER=./xdp-filter
ALL_TESTS="test_load test_ports"

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
    declare -a PROGS_B=(xdpfilt_blk_tcp.o xdpfilt_blk_udp.o xdpfilt_blk_ip.o xdpfilt_blk_ip.o xdpfilt_blk_eth.o xdpfilt_blk_all.o)
    declare -a PROGS_W=(xdpfilt_wht_tcp.o xdpfilt_wht_udp.o xdpfilt_wht_ip.o xdpfilt_wht_ip.o xdpfilt_wht_eth.o xdpfilt_wht_all.o)
    local len=${#FEATS[@]}

    for (( i=0; i<$len; i++ )); do
        if ! try_feat ${FEATS[$i]} ${PROGS_B[$i]}; then
            return 1
        fi
        if ! try_feat ${FEATS[$i]} ${PROGS_B[$i]} --mode skb; then
            return 1
        fi
        if ! try_feat ${FEATS[$i]} ${PROGS_W[$i]} "-w"; then
            return 1
        fi
        if ! try_feat ${FEATS[$i]} ${PROGS_W[$i]} "-w" --mode skb; then
            return 1
        fi
    done

    if [ -d /sys/fs/bpf/xdp-filter ]; then
        die "/sys/fs/bpf/xdp-filter still exists!"
    fi
}

check_port()
{
    local type=$1
    local port=$2
    local expect=$3
    echo "Checking $type port $port $expect"
    PID=$(start_background tcpdump -epni $NS "$type dst port $port")
    echo "Started listener as $PID"
    [[ "$type" == "tcp" ]] && ns_exec nc -w 1 -z "$OUTSIDE_IP6" $port
    [[ "$type" == "udp" ]] && ns_exec bash -c "echo test | nc -w 1 -u $OUTSIDE_IP6 $port"
    sleep 1
    output=$(stop_background $PID)
    echo "$output"

    if [[ "$expect" == "OK" ]]; then
        regex="1 packet captured"
    else
        regex="0 packets captured"
    fi

    if [[ "$output" =~ $regex ]]; then
        return 0
    else
        exit 1
    fi
}

test_ports()
{
    trap on_error ERR
    local TEST_PORT=10000

    # blacklist mode
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

    # whitelist mode
    check_run $XDP_FILTER load -w $NS -v
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


cleanup_tests()
{
    $XDP_FILTER unload --all
}
