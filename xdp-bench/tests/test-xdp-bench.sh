XDP_LOADER=${XDP_LOADER:-./xdp-loader}
XDP_BENCH=${XDP_BENCH:-./xdp-bench}
ALL_TESTS="test_drop test_pass test_tx test_rxq_stats test_redirect test_redirect_cpu test_redirect_map test_redirect_map_egress test_redirect_multi test_redirect_multi_egress"

test_basic()
{
    action=$1

    export XDP_SAMPLE_IMMEDIATE_EXIT=1
    check_run $XDP_BENCH $action $NS -vv
    check_run $XDP_BENCH $action $NS -p read-data -vv
    check_run $XDP_BENCH $action $NS -p swap-macs -vv
    check_run $XDP_BENCH $action $NS -m skb -vv
    check_run $XDP_BENCH $action $NS -e -vv
}

test_drop()
{
    test_basic drop
}
test_pass()
{
    test_basic pass
}
test_tx()
{
    test_basic tx
}

test_rxq_stats()
{
    skip_if_missing_veth_rxq

    export XDP_SAMPLE_IMMEDIATE_EXIT=1
    check_run $XDP_BENCH drop $NS -r -vv
}

test_redirect()
{
    export XDP_SAMPLE_IMMEDIATE_EXIT=1
    check_run ip link add dev btest0 type veth peer name btest1
    check_run $XDP_BENCH redirect btest0 btest1 -vv
    check_run $XDP_BENCH redirect btest0 btest1 -s -vv
    check_run $XDP_BENCH redirect btest0 btest1 -m skb -vv
    check_run $XDP_BENCH redirect btest0 btest1 -e -vv
    ip link del dev btest0
}

test_redirect_cpu()
{
    skip_if_missing_cpumap_attach

    export XDP_SAMPLE_IMMEDIATE_EXIT=1
    check_run ip link add dev btest0 type veth peer name btest1
    check_run $XDP_BENCH redirect-cpu btest0 -c 0 -vv
    check_run $XDP_BENCH redirect-cpu btest0 -c 0 -m skb -vv
    check_run $XDP_BENCH redirect-cpu btest0 -c 0 -p touch -vv
    check_run $XDP_BENCH redirect-cpu btest0 -c 0 -p round-robin -vv
    check_run $XDP_BENCH redirect-cpu btest0 -c 0 -p l4-proto -vv
    check_run $XDP_BENCH redirect-cpu btest0 -c 0 -p l4-filter -vv
    check_run $XDP_BENCH redirect-cpu btest0 -c 0 -p l4-hash -vv

    is_progmap_supported || export LIBXDP_SKIP_DISPATCHER=1
    check_run $XDP_BENCH redirect-cpu btest0 -c 0 -r drop -vv
    check_run $XDP_BENCH redirect-cpu btest0 -c 0 -r pass -vv
    check_run $XDP_BENCH redirect-cpu btest0 -c 0 -r redirect -D btest1  -vv
    ip link del dev btest0
}

test_redirect_map()
{
    export XDP_SAMPLE_IMMEDIATE_EXIT=1
    check_run ip link add dev btest0 type veth peer name btest1
    check_run $XDP_BENCH redirect-map btest0 btest1 -vv
    check_run $XDP_BENCH redirect-map btest0 btest1 -s -vv
    check_run $XDP_BENCH redirect-map btest0 btest1 -m skb -vv
    check_run $XDP_BENCH redirect-map btest0 btest1 -e -vv
    ip link del dev btest0
}

test_redirect_map_egress()
{
    skip_if_missing_cpumap_attach

    export XDP_SAMPLE_IMMEDIATE_EXIT=1
    check_run ip link add dev btest0 type veth peer name btest1
    is_progmap_supported || export LIBXDP_SKIP_DISPATCHER=1
    check_run $XDP_BENCH redirect-map btest0 btest1 -X -vv
    ip link del dev btest0
}

test_redirect_multi()
{
    export XDP_SAMPLE_IMMEDIATE_EXIT=1
    check_run ip link add dev btest0 type veth peer name btest1
    check_run ip link add dev btest2 type veth peer name btest3
    check_run $XDP_BENCH redirect-multi btest0 btest1 btest2 btest3 -vv
    check_run $XDP_BENCH redirect-multi btest0 btest1 btest2 btest3 -s -vv
    check_run $XDP_BENCH redirect-multi btest0 btest1 btest2 btest3 -m skb -vv
    check_run $XDP_BENCH redirect-multi btest0 btest1 btest2 btest3 -e -vv
    ip link del dev btest0
    ip link del dev btest2
}

test_redirect_multi_egress()
{
    skip_if_missing_cpumap_attach

    export XDP_SAMPLE_IMMEDIATE_EXIT=1
    is_progmap_supported || export LIBXDP_SKIP_DISPATCHER=1
    check_run ip link add dev btest0 type veth peer name btest1
    check_run ip link add dev btest2 type veth peer name btest3

    check_run $XDP_BENCH redirect-multi btest0 btest1 btest2 btest3 -X -vv

    ip link del dev btest0
    ip link del dev btest2
}

cleanup_tests()
{
    ip link del dev btest0 >/dev/null 2>&1
    ip link del dev btest2 >/dev/null 2>&1
    $XDP_LOADER unload $NS --all >/dev/null 2>&1
    $XDP_LOADER clean >/dev/null 2>&1
}
