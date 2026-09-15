XDP_LOADER=${XDP_LOADER:-./xdp-loader}
XDP_FORWARD=${XDP_FORWARD:-./xdp-forward}
ALL_TESTS="test_ping test_load test_load_high_ifindex test_fwd_full test_fwd_direct test_flowtable test_vlan_userspace test_vlan_qinq test_vlan_rewrite"

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
    check_run $XDP_FORWARD load -f flowtable ${NS_NAMES[@]}

    PID=$(start_socat_ns "socat -dd -4 TCP-LISTEN:10000,reuseaddr,fork -")
    check_run ip netns exec ${NS_NAMES[0]} socat ${INPUT_FILE} TCP4:${OUTSIDE_IP4}:12345,connect-timeout=0.2
    stop_background $PID

    PID=$(start_socat_ns "socat -dd -6 TCP-LISTEN:10000,reuseaddr,fork -")
    check_run ip netns exec ${NS_NAMES[0]} socat ${INPUT_FILE} TCP6:[${OUTSIDE_IP6}]:12345,connect-timeout=0.2
    stop_background $PID

    check_run $XDP_FORWARD unload ${NS_NAMES[@]}
}

# VLAN forwarding tests. The feature is always built; it arms itself at
# load time when VLAN uppers exist on the configured interfaces.
vlan_topo_cleanup()
{
    for n in xfv-cl xfv-rt xfv-sv; do
        ip netns del $n
    done 2>/dev/null
    return 0
}

vlan_topo_setup()
{
    # cl --veth-- rt --veth-- sv; rt's sv-side leg carries an 802.1Q upper
    # (vlan 100) plus a stacked vlan 200 on top of it for the QinQ test.
    # VLAN offload is disabled everywhere so tags are in-band: veth peers
    # otherwise deliver the outermost tag out of band, where native XDP
    # never sees it.
    vlan_topo_cleanup
    check_run ip netns add xfv-cl
    check_run ip netns add xfv-rt
    check_run ip netns add xfv-sv
    check_run ip -n xfv-cl link add cl0 type veth peer name rtA netns xfv-rt
    check_run ip -n xfv-rt link add rtB type veth peer name sv0 netns xfv-sv

    check_run ip -n xfv-rt link set rtA up
    check_run ip -n xfv-rt link set rtB up
    check_run ip -n xfv-rt link add link rtB name rtB.100 type vlan id 100
    check_run ip -n xfv-rt link set rtB.100 up
    check_run ip -n xfv-rt addr add 10.199.1.1/24 dev rtA
    check_run ip -n xfv-rt addr add 10.199.2.1/24 dev rtB.100
    check_run ip -n xfv-rt link add link rtB.100 name rtB.100.200 type vlan id 200
    check_run ip -n xfv-rt link set rtB.100.200 up
    check_run ip -n xfv-rt addr add 10.199.3.1/24 dev rtB.100.200
    check_run ip netns exec xfv-rt sysctl -qw net.ipv4.conf.all.forwarding=1

    check_run ip -n xfv-cl link set cl0 up
    check_run ip -n xfv-cl addr add 10.199.1.2/24 dev cl0
    check_run ip -n xfv-cl addr add 10.199.1.3/32 dev cl0
    check_run ip -n xfv-cl route add default via 10.199.1.1

    check_run ip -n xfv-sv link set sv0 up
    check_run ip -n xfv-sv link add link sv0 name sv0.100 type vlan id 100
    check_run ip -n xfv-sv link set sv0.100 up
    check_run ip -n xfv-sv addr add 10.199.2.2/24 dev sv0.100
    check_run ip -n xfv-sv route add default via 10.199.2.1
    check_run ip -n xfv-sv link add link sv0.100 name sv0.100.200 type vlan id 200
    check_run ip -n xfv-sv link set sv0.100.200 up
    check_run ip -n xfv-sv addr add 10.199.3.2/24 dev sv0.100.200
    check_run ip -n xfv-sv route add 10.199.1.3/32 via 10.199.3.1

    local cl_mac sv_mac
    cl_mac=$(ip -n xfv-cl link show cl0 | awk '/link\/ether/{print $2}')
    sv_mac=$(ip -n xfv-sv link show sv0.100 | awk '/link\/ether/{print $2}')
    check_run ip -n xfv-rt neigh replace 10.199.1.2 dev rtA lladdr $cl_mac nud permanent
    check_run ip -n xfv-rt neigh replace 10.199.1.3 dev rtA lladdr $cl_mac nud permanent
    check_run ip -n xfv-rt neigh replace 10.199.2.2 dev rtB.100 lladdr $sv_mac nud permanent

    check_run ip netns exec xfv-cl ethtool -K cl0 txvlan off rxvlan off
    check_run ip netns exec xfv-rt ethtool -K rtA txvlan off rxvlan off
    check_run ip netns exec xfv-rt ethtool -K rtB txvlan off rxvlan off
    check_run ip netns exec xfv-sv ethtool -K sv0 txvlan off rxvlan off

    # veth native-XDP xmit needs a program on the peer devices
    check_run ip -n xfv-cl link set cl0 xdp obj ../lib/testing/xdp_pass.o sec xdp
    check_run ip -n xfv-sv link set sv0 xdp obj ../lib/testing/xdp_pass.o sec xdp
}

vlan_fwd_count()
{
    ip netns exec xfv-rt awk '/^Ip:/{if(++n==2) print $7}' /proc/net/snmp
}

test_vlan_userspace()
{
    local f0 f1

    # veth NAPI GRO support added this symbol; forwarding won't work without it
    skip_if_missing_kernel_symbol veth_set_features

    vlan_topo_setup

    check_run ip netns exec xfv-rt $XDP_FORWARD load -m native rtA rtB
    f0=$(vlan_fwd_count)
    check_run ip netns exec xfv-cl ping -c 3 -i 0.2 -W 2 10.199.2.2
    f1=$(vlan_fwd_count)
    # the ping crosses a VLAN egress (push) and returns through a tagged
    # ingress (pop); XDP must forward it all, so the kernel counter stays flat
    if [ $((f1 - f0)) -gt 1 ]; then
        echo "single-tag traffic went through the stack (ForwDatagrams +$((f1 - f0)))"
        exit 1
    fi
    check_run ip netns exec xfv-rt $XDP_FORWARD unload rtA rtB
}

test_vlan_qinq()
{
    local f0 f1

    skip_if_missing_kernel_symbol veth_set_features

    vlan_topo_setup

    check_run ip netns exec xfv-rt $XDP_FORWARD load -m native rtA rtB
    f0=$(vlan_fwd_count)
    check_run ip netns exec xfv-sv ping -c 3 -i 0.2 -W 2 -I 10.199.3.2 10.199.1.3
    f1=$(vlan_fwd_count)
    # stacked tags must fail closed to the stack: the ping succeeds and the
    # kernel forwards it in both directions
    if [ $((f1 - f0)) -lt 5 ]; then
        echo "stacked-VLAN traffic did not traverse the stack (ForwDatagrams +$((f1 - f0)))"
        exit 1
    fi
    check_run ip netns exec xfv-rt $XDP_FORWARD unload rtA rtB
}

test_vlan_rewrite()
{
    local cl_mac f0 f1

    skip_if_missing_kernel_symbol veth_set_features

    vlan_topo_setup

    # give the client leg a VLAN too, so both directions of the ping are
    # tagged-to-tagged rewrites (vlan 300 in, vlan 100 out, and back)
    check_run ip -n xfv-rt link add link rtA name rtA.300 type vlan id 300
    check_run ip -n xfv-rt link set rtA.300 up
    check_run ip -n xfv-rt addr add 10.199.4.1/24 dev rtA.300
    check_run ip -n xfv-cl link add link cl0 name cl0.300 type vlan id 300
    check_run ip -n xfv-cl link set cl0.300 up
    check_run ip -n xfv-cl addr add 10.199.4.2/24 dev cl0.300
    check_run ip -n xfv-cl route add 10.199.2.0/24 via 10.199.4.1
    cl_mac=$(ip -n xfv-cl link show cl0 | awk '/link\/ether/{print $2}')
    check_run ip -n xfv-rt neigh replace 10.199.4.2 dev rtA.300 lladdr $cl_mac nud permanent

    check_run ip netns exec xfv-rt $XDP_FORWARD load -m native rtA rtB
    f0=$(vlan_fwd_count)
    check_run ip netns exec xfv-cl ping -c 3 -i 0.2 -W 2 10.199.2.2
    f1=$(vlan_fwd_count)
    # both directions rewrite the TCI in place; XDP must forward it all
    if [ $((f1 - f0)) -gt 1 ]; then
        echo "rewrite traffic went through the stack (ForwDatagrams +$((f1 - f0)))"
        exit 1
    fi
    check_run ip netns exec xfv-rt $XDP_FORWARD unload rtA rtB
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
        vlan_topo_cleanup
    } >/dev/null 2>&1
}
