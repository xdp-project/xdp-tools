XDP_LOADER=${XDP_LOADER:-./xdp-loader}
ALL_TESTS="test_load test_section test_prog_name test_load_adjust_tail test_load_multi test_load_incremental test_load_clobber test_features"

test_load()
{
    check_run $XDP_LOADER load $NS $TEST_PROG_DIR/xdp_drop.o -vv
    check_run $XDP_LOADER unload $NS --all -vv
}

test_section()
{
    check_run $XDP_LOADER load $NS $TEST_PROG_DIR/xdp_drop.o -s xdp -vv
    check_run $XDP_LOADER unload $NS --all -vv
}

test_prog_name()
{
	check_run $XDP_LOADER load $NS $TEST_PROG_DIR/xdp_drop.o -n xdp_drop -vv
	check_run $XDP_LOADER unload $NS --all -vv
}

test_load_adjust_tail()
{
    check_run $XDP_LOADER load $NS $TEST_PROG_DIR/xdp_adjust_tail.o -vv

    # Need to load twice to test freplace of both the top-level dispatcher
    # function as well as sub-functions for multi-prog; but only do this if we
    # the kernel actually supports loading multiple programs
    if is_multiprog_supported; then
        check_run $XDP_LOADER load $NS $TEST_PROG_DIR/xdp_adjust_tail.o -vv
    fi
    check_run $XDP_LOADER unload $NS --all -vv
}

check_progs_loaded()
{
    local iface="$1"
    local num=$2
    local num_loaded

    num_loaded=$($XDP_LOADER status $NS | grep -c '=>')
    if [ "$num_loaded" -ne "$num" ]; then
        echo "Expected $num programs loaded, found $num_loaded"
        exit 1
    fi
}

test_load_multi()
{
    skip_if_legacy_fallback

    check_run $XDP_LOADER load $NS $TEST_PROG_DIR/xdp_drop.o $TEST_PROG_DIR/xdp_pass.o -vv
    check_progs_loaded $NS 2
    check_run $XDP_LOADER unload $NS --all -vv
}

test_load_incremental()
{
    skip_if_legacy_fallback

    local output
    local ret
    local id

    check_run $XDP_LOADER load $NS $TEST_PROG_DIR/xdp_drop.o -vv

    check_progs_loaded $NS 1

    output=$($XDP_LOADER load $NS $TEST_PROG_DIR/xdp_pass.o -vv 2>&1)
    ret=$?

    if [ "$ret" -ne "0" ] && echo $output | grep -q "Falling back to loading single prog"; then
        ret=$SKIPPED_TEST
        check_run $XDP_LOADER unload $NS --all -vv
    else
        check_progs_loaded $NS 2

        id=$($XDP_LOADER status $NS | grep xdp_pass | awk '{print $4}')
        check_run $XDP_LOADER unload $NS --id $id
        check_progs_loaded $NS 1

        id=$($XDP_LOADER status $NS | grep xdp_drop | awk '{print $4}')
        check_run $XDP_LOADER unload $NS --id $id
        check_progs_loaded $NS 0
    fi
    return $ret
}

test_load_clobber()
{
    skip_if_legacy_fallback

    check_run env LIBXDP_SKIP_DISPATCHER=1 $XDP_LOADER load $NS $TEST_PROG_DIR/xdp_drop.o  -vv
    check_progs_loaded $NS 0 # legacy prog so should show up as 0
    $XDP_LOADER load $NS $TEST_PROG_DIR/xdp_pass.o -vv
    ret=$?

    if [ "$ret" -eq "0" ]; then
        echo "Should not have been able to load prog with legacy prog loaded"
        return 1
    fi
    check_progs_loaded $NS 0
    check_run $XDP_LOADER unload $NS --all -vv
}

check_xdp_feature()
{
    check_run ip link add dev v0 type veth peer name v1

    $XDP_LOADER features v0 | grep "$1" | grep -q "$2"
    ret=$?

    ip link del dev v0

    [ $ret -eq 1 ] && exit 1
}

test_features()
{
    skip_if_missing_kernel_symbol xdp_set_features_flag

    check_xdp_feature NETDEV_XDP_ACT_BASIC yes
    check_xdp_feature NETDEV_XDP_ACT_REDIRECT yes
    check_xdp_feature NETDEV_XDP_ACT_NDO_XMIT no
    check_xdp_feature NETDEV_XDP_ACT_XSK_ZEROCOPY no
    check_xdp_feature NETDEV_XDP_ACT_HW_OFFLOAD no
    check_xdp_feature NETDEV_XDP_ACT_RX_SG yes
    check_xdp_feature NETDEV_XDP_ACT_NDO_XMIT_SG no

    return 0
}

cleanup_tests()
{
    $XDP_LOADER unload $NS --all >/dev/null 2>&1
}
