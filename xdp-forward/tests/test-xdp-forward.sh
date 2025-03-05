XDP_LOADER=${XDP_LOADER:-./xdp-loader}
XDP_FORWARD=${XDP_FORWARD:-./xdp-forward}
ALL_TESTS="test_ping test_load test_load_high_ifindex test_fwd_full test_fwd_direct test_flowtable"

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

test_load_high_ifindex()
{
    # Add a bunch of interfaces to run up the ifindex counter
    for i in $(seq 64); do
        ip link add dev veth-forw-test type veth
        ip link del dev veth-forw-test
    done

    ip link add dev veth-forw-test type veth
    check_run $XDP_FORWARD load veth-forw-test
    check_run $XDP_FORWARD unload veth-forw-test
}

test_fwd_full()
{
    # veth NAPI GRO support added this symbol; forwarding won't work without it
    skip_if_missing_kernel_symbol veth_set_features

    check_run $XDP_FORWARD load -f fib -F full ${NS_NAMES[@]}
    for ip in "${ALL_INSIDE_IP4[@]}"; do
        check_run ns_exec ping -c 1 -W 2 $ip
    done
    for ip in "${ALL_INSIDE_IP6[@]}"; do
        check_run ns_exec $PING6 -c 1 -W 2 $ip
    done
    check_run $XDP_FORWARD unload ${NS_NAMES[@]}
}

test_fwd_direct()
{
    # veth NAPI GRO support added this symbol; forwarding won't work without it
    skip_if_missing_kernel_symbol veth_set_features

    check_run $XDP_FORWARD load -f fib -F direct ${NS_NAMES[@]}
    for ip in "${ALL_INSIDE_IP4[@]}"; do
        check_run ns_exec ping -c 1 -W 2 $ip
    done
    for ip in "${ALL_INSIDE_IP6[@]}"; do
        check_run ns_exec $PING6 -c 1 -W 2 $ip
    done
    check_run $XDP_FORWARD unload ${NS_NAMES[@]}
}

test_flowtable()
{
    local INPUT_FILE="${STATEDIR}/in_$$_$RANDOM"

    # veth NAPI GRO support added this symbol; forwarding won't work without it
    skip_if_missing_kernel_symbol veth_set_features

    # disable {tx,rx} checksum offload since it is not currently suported
    # by XDP_REDIRECT
    for n in ${NS_NAMES[@]}; do
        ip netns exec $n ethtool -K veth0 tx-checksumming off rx-checksumming off
        ethtool -K $n tx-checksumming off rx-checksumming off
    done

    # create data to send via tcp
    dd if=/dev/urandom of="${INPUT_FILE}" bs=8192 count=32 status=none

    # create flowtable configuration in the main namespace
    check_run nft -f /dev/stdin <<EOF
table inet nat {
    # enable DNAT to server <ip:port> in pre-routing chain
    chain prerouting {
        type nat hook prerouting priority filter; policy accept;
        iifname == "${NS_NAMES[0]}" meta nfproto ipv4 tcp dport 12345 dnat ip to ${ALL_INSIDE_IP4[-1]}:10000
        iifname == "${NS_NAMES[0]}" meta nfproto ipv6 tcp dport 12345 dnat ip6 to [${ALL_INSIDE_IP6[-1]}]:10000
    }
    # enable SNAT of the client ip via masquerading in post-routing chain
    chain postrouting {
        type nat hook postrouting priority filter; policy accept;
        oifname "${NS_NAMES[-1]}" masquerade
    }
}
table inet filter {
    flowtable ft {
        hook ingress priority filter
        devices = { ${NS_NAMES[0]}, ${NS_NAMES[-1]} }
    }
    chain forward {
        type filter hook forward priority filter
        meta l4proto { tcp } flow add @ft
    }
}
EOF

    # check if bpf flowtable lookup is available
    skip_if_missing_kernel_symbol bpf_xdp_flow_lookup

    # Add some nft rules to check {dnat/snat} is done properly in
    # the main namespace
    check_run ip netns exec ${NS_NAMES[-1]} nft -f /dev/stdin <<EOF
table inet filter {
    chain input {
        type filter hook input priority 0; policy drop
        ip saddr $OUTSIDE_IP4 ip daddr ${ALL_INSIDE_IP4[-1]} tcp dport 10000 accept
        ip6 saddr $OUTSIDE_IP6 ip6 daddr ${ALL_INSIDE_IP6[-1]} tcp dport 10000 accept
    }
}
EOF
    # wait a bit to configure nft
    sleep 2

    check_run $XDP_FORWARD load -f flowtable ${NS_NAMES[@]}

    PID=$(start_background_ns_devnull "socat -4 TCP-LISTEN:10000,reuseaddr,fork -")
    check_run ip netns exec ${NS_NAMES[0]} socat ${INPUT_FILE} TCP4:${OUTSIDE_IP4}:12345,connect-timeout=1
    stop_background $PID

    PID=$(start_background_ns_devnull "socat -6 TCP-LISTEN:10000,reuseaddr,fork -")
    check_run ip netns exec ${NS_NAMES[0]} socat ${INPUT_FILE} TCP6:[${OUTSIDE_IP6}]:12345,connect-timeout=1
    stop_background $PID

    check_run $XDP_FORWARD unload ${NS_NAMES[@]}
}

cleanup_tests()
{
    # enable {tx,rx} checksum offload
    for n in ${NS_NAMES[@]}; do
        ip netns exec $n ethtool -K veth0 tx-checksumming on rx-checksumming on
        ethtool -K $n tx-checksumming on rx-checksumming on
    done >/dev/null 2>&1
    {
        $XDP_FORWARD unload ${NS_NAMES[@]}
        $XDP_LOADER unload $NS --all
        check_run ip netns exec ${NS_NAMES[-1]} nft flush ruleset
        check_run nft flush ruleset
        ip link del dev veth-forw-test
    } >/dev/null 2>&1
}
