XDP_LOADER=${XDP_LOADER:-./xdp-loader}
XDP_FORWARD=${XDP_FORWARD:-./xdp-forward}
ALL_TESTS="test_ping test_load test_fwd_full test_fwd_direct"


test_ping()
{
    for ip in "${ALL_INSIDE_IP4[@]}"; do
        check_run ping -c 1 -W 2 $ip
        check_run ns_exec ping -c 1 -W 2 $ip
    done
    for ip in "${ALL_INSIDE_IP6[@]}"; do
        check_run $PING6 -c 1 -W 2 $ip
        check_run ns_exec $PING6 -c 1 -W 2 $ip
    done
}

test_load()
{

    check_run $XDP_FORWARD load ${NS_NAMES[@]}
    check_run $XDP_FORWARD unload ${NS_NAMES[@]}
}

test_fwd_full()
{
    # veth NAPI GRO support added this symbol; forwarding won't work without it
    skip_if_missing_kernel_symbol veth_set_features

    check_run $XDP_FORWARD load -f fib-full ${NS_NAMES[@]}
    for ip in "${ALL_INSIDE_IP4[@]}"; do
        check_run ns_exec ping -c 1 -W 2 $ip
    done
    for ip in "${ALL_INSIDE_IP4[@]}"; do
        check_run ns_exec ping -c 1 -W 2 $ip
    done
    check_run $XDP_FORWARD unload ${NS_NAMES[@]}
}

test_fwd_direct()
{
    # veth NAPI GRO support added this symbol; forwarding won't work without it
    skip_if_missing_kernel_symbol veth_set_features

    check_run $XDP_FORWARD load -f fib-direct ${NS_NAMES[@]}
    for ip in "${ALL_INSIDE_IP4[@]}"; do
        check_run ns_exec ping -c 1 -W 2 $ip
    done
    for ip in "${ALL_INSIDE_IP4[@]}"; do
        check_run ns_exec ping -c 1 -W 2 $ip
    done
    check_run $XDP_FORWARD unload ${NS_NAMES[@]}
}

cleanup_tests()
{
    $XDP_FORWARD unload ${NS_NAMES[@]} >/dev/null 2>&1
    $XDP_LOADER unload $NS --all >/dev/null 2>&1
}
