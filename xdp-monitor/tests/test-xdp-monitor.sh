XDP_LOADER=${XDP_LOADER:-./xdp-loader}
XDP_MONITOR=${XDP_MONITOR:-./xdp-monitor}
ALL_TESTS="test_monitor"

test_monitor()
{
    export XDP_SAMPLE_IMMEDIATE_EXIT=1
    check_run $XDP_MONITOR -vv
    check_run $XDP_MONITOR -s -vv
    check_run $XDP_MONITOR -e -vv
}
