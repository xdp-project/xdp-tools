XDP_LOADER=${XDP_LOADER:-./xdp-loader}
XDP_TRAFFICGEN=${XDP_TRAFFICGEN:-./xdp-trafficgen}
ALL_TESTS="test_udp test_tcp test_no_support"

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
