XDP_LOADER=${XDP_LOADER:-./xdp-loader}
ALL_TESTS="test_load test_section test_load_multi test_load_incremental"

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

cleanup_tests()
{
    $XDP_LOADER unload $NS --all >/dev/null 2>&1
}
