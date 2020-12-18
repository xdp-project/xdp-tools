XDP_LOADER=${XDP_LOADER:-./xdp-loader}
ALL_TESTS="test_load test_section"

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

cleanup_tests()
{
    $XDP_LOADER unload $NS --all >/dev/null 2>&1
}
