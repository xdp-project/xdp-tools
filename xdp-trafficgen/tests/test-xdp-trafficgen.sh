XDP_LOADER=${XDP_LOADER:-./xdp-loader}
XDP_TRAFFICGEN=${XDP_TRAFFICGEN:-./xdp-trafficgen}
ALL_TESTS="test_udp test_tcp"

PIDS=""

skip_if_missing_kernel_support()
{
    $XDP_TRAFFICGEN probe
    ret=$?
    if [ "$ret" -eq "161" ]; then
        exit $SKIPPED_TEST
    elif [ "$ret" -ne "0" ]; then
        exit 1
    fi
}

test_udp()
{
    skip_if_missing_kernel_support
    export XDP_SAMPLE_IMMEDIATE_EXIT=1

    check_run $XDP_TRAFFICGEN udp $NS -n 1
}

test_tcp()
{
    skip_if_missing_kernel_support
    export XDP_SAMPLE_IMMEDIATE_EXIT=1

    PID=$(start_background_ns_devnull "nc -6 -l 10000")
    $XDP_TRAFFICGEN tcp -i $NS $INSIDE_IP6 -n 1
    res=$?
    stop_background $PID
    return $res
}

cleanup_tests()
{
    $XDP_LOADER unload $NS --all >/dev/null 2>&1
    $XDP_LOADER clean >/dev/null 2>&1
}
