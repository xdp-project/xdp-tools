XDP_LOADER=${XDP_LOADER:-./xdp-loader}
ALL_TESTS="test_load test_unload"

test_load()
{
    $XDP_LOADER load $NS $TEST_PROG_DIR/xdp_drop.o -vv
}

test_unload()
{
    $XDP_LOADER unload $NS --all -vv
}
