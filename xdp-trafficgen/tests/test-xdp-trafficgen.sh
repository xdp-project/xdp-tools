XDP_LOADER=${XDP_LOADER:-./xdp-loader}
XDP_TRAFFICGEN=${XDP_TRAFFICGEN:-./xdp-trafficgen}
ALL_TESTS="test_udp test_tcp test_no_support test_xsk_udp"

PIDS=""

skip_if_missing_kernel_support()
{
    $XDP_TRAFFICGEN probe || exit $SKIPPED_TEST
}

skip_if_missing_kernel_features()
{
    out=$($XDP_TRAFFICGEN probe -i $NS 2>&1)
    ERR_REGEX1="Interface $NS does not support sending packets via XDP."
    ERR_REGEX2="Couldn't query XDP features for interface $NS"

    if [[ $out =~ $ERR_REGEX1 ]] || [[ $out =~ $ERR_REGEX2 ]]; then
        exit $SKIPPED_TEST
    fi
}

test_udp()
{
    skip_if_missing_kernel_support
    export XDP_SAMPLE_IMMEDIATE_EXIT=1

    check_run $XDP_TRAFFICGEN udp $NS -n 1
}

test_xsk_one()
{
    action=$1
    shift

    export XDP_SAMPLE_IMMEDIATE_EXIT=1
    check_run ip link add dev btest0 type veth peer name btest1
    check_run $XDP_TRAFFICGEN $action btest0 "$@" -vv
    ip link del dev btest0
}

test_xsk_udp()
{
    local action
    local res
    local hugepg

    action=xsk-udp

    test_xsk_one $action
    test_xsk_one $action --no-need-wakeup
    test_xsk_one $action --shared-umem
    test_xsk_one $action -M aa:bb:cc:dd:ee:ff
    test_xsk_one $action -P 0x12345678
    test_xsk_one $action -Q
    test_xsk_one $action -T 1000
    test_xsk_one $action -V
    test_xsk_one $action -W SCHED_FIFO -U 50
    test_xsk_one $action -b 32
    test_xsk_one $action -c 1
    test_xsk_one $action -c copy
    test_xsk_one $action -d 1
    test_xsk_one $action -f 2048
    test_xsk_one $action -m aa:bb:cc:dd:ee:ff
    test_xsk_one $action -p
    test_xsk_one $action -q 0
    test_xsk_one $action -s 1024
    hugepg=$(cat /proc/sys/vm/nr_hugepages)
    if [ "$hugepg" -lt "8" ]; then
        echo 8 > /proc/sys/vm/nr_hugepages
        res=$?
    else
        res=0
    fi
    if [ "$res" = "0" ]; then
        test_xsk_one $action -u
        echo $hugepg > /proc/sys/vm/nr_hugepages
    fi
    test_xsk_one $action -w BOOTTIME
    test_xsk_one $action -w MONOTONIC
    test_xsk_one $action -x -a
    test_xsk_one $action -y
}


test_tcp()
{
    skip_if_missing_kernel_support
    export XDP_SAMPLE_IMMEDIATE_EXIT=1

    PID=$(start_background_ns_devnull "socat -6 TCP-LISTEN:10000,reuseaddr,fork -")
    $XDP_TRAFFICGEN tcp -i $NS $INSIDE_IP6 -n 1
    res=$?
    stop_background $PID
    return $res
}

test_no_support()
{
    skip_if_missing_kernel_support
    skip_if_missing_kernel_features
    export XDP_SAMPLE_IMMEDIATE_EXIT=1

    ip link add dev xdptest0 type veth || return 1

    out=$($XDP_TRAFFICGEN udp xdptest0 -n 1 2>&1)
    err=$?

    ERR_REGEX="Interface xdptest0 does not support sending packets via XDP."

    if [ $err -eq 0 ] || ! [[ $out =~ $ERR_REGEX ]]; then
        echo $out
        return 1
    fi
}

cleanup_tests()
{
    $XDP_LOADER unload $NS --all >/dev/null 2>&1
    $XDP_LOADER clean >/dev/null 2>&1
}
