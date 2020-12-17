#
# Test scrip to do basic xdpdump checks
#
# shellcheck disable=2039
#
ALL_TESTS="test_help test_interfaces test_capt_pcap test_capt_pcapng test_capt_term test_exitentry test_snap test_multi_pkt test_perf_wakeup test_promiscuous test_none_xdp test_pname_pars"

XDPDUMP=${XDPDUMP:-./xdpdump}
XDP_LOADER=${XDP_LOADER:-../xdp-loader/xdp-loader}

RESULT=""

print_result()
{
    echo "$RESULT"
    if [ -n "$1" ]; then
        echo "ERROR: $1"
    fi
}

test_help()
{
    local XDPDUMP_HELP_TEXT
    XDPDUMP_HELP_TEXT=$(cat <<-END

Usage: xdpdump [options]

 XDPDump tool to dump network traffic

Options:
     --rx-capture <mode>    Capture point for the rx direction (valid values: entry,exit)
 -D, --list-interfaces      Print the list of available interfaces
 -i, --interface <ifname>   Name of interface to capture on
     --perf-wakeup <events>  Wake up xdpdump every <events> packets
 -p, --program-names <prog>  Specific program to attach to
 -P, --promiscuous-mode     Open interface in promiscuous mode
 -s, --snapshot-length <snaplen>  Minimum bytes of packet to capture
     --use-pcap             Use legacy pcap format for XDP traces
 -w, --write <file>         Write raw packets to pcap file
 -x, --hex                  Print the full packet in hex
 -v, --verbose              Enable verbose logging (-vv: more verbose)
     --version              Display version information
 -h, --help                 Show this help

END
          )

    $XDPDUMP --help | grep -q "\-\-perf-wakeup"
    if [ $? -eq 1 ]; then
        XDPDUMP_HELP_TEXT=$(echo "$XDPDUMP_HELP_TEXT" | sed '/     --perf-wakeup <events>  Wake up xdpdump every <events> packets/d')
    fi

    RESULT=$($XDPDUMP --help)
    if [ "$RESULT" != "$XDPDUMP_HELP_TEXT" ]; then
        print_result "The --help output failed"
        return 1
    fi
    RESULT=$($XDPDUMP -h)
    if [ "$RESULT" != "$XDPDUMP_HELP_TEXT" ]; then
        print_result "The -h output failed"
        return 1
    fi
}

test_interfaces()
{
    local NO_PROG_REGEX="([0-9]+ +$NS +<No XDP program loaded!>)"
    local PROG_REGEX="([0-9]+ +$NS +xdp_dispatcher\(\)[[:space:]]+xdp_drop\(\))"

    RESULT=$($XDPDUMP -D)
    if ! [[ $RESULT =~ $NO_PROG_REGEX ]]; then
        print_result "Failed showing test interface with no XPD program loaded"
        return 1
    fi

    RESULT=$($XDPDUMP --list-interfaces)
    if ! [[ $RESULT =~ $NO_PROG_REGEX ]]; then
        print_result "Failed showing test interface with no XPD program loaded"
        return 1
    fi

    $XDP_LOADER load "$NS" "$TEST_PROG_DIR/xdp_drop.o"

    RESULT=$($XDPDUMP -D)
    if ! [[ $RESULT =~ $PROG_REGEX ]]; then
        print_result "Failed showing test interface with XPD program loaded"
        return 1
    fi

    $XDP_LOADER unload "$NS" --all
}

test_capt_pcap()
{
    local PASS_PKT="IP6 $INSIDE_IP6 > $OUTSIDE_IP6: ICMP6, echo reply, seq 1, length 64"

    $PING6 -W 2 -c 1 "$INSIDE_IP6" || return 1
    $XDP_LOADER load "$NS" "$TEST_PROG_DIR/test_long_func_name.o" || return 1

    PID=$(start_background "$XDPDUMP -i $NS --use-pcap -w - 2> /dev/null | tcpdump -r - -n")
    $PING6 -W 2 -c 1 "$INSIDE_IP6" || return 1
    RESULT=$(stop_background "$PID")

    $XDP_LOADER unload "$NS" --all || return 1

    if [[ "$RESULT" != *"$PASS_PKT"* ]]; then
        print_result "IPv6 packet not received"
        return 1
    fi
}

test_capt_pcapng()
{
    local PCAP_FILE="/tmp/${NS}_PID_$$_$RANDOM.pcap"
    local PASS_PKT="IP6 $INSIDE_IP6 > $OUTSIDE_IP6: ICMP6, echo reply, seq 1, length 64"
    local HW=$(uname -m | sed -e 's/[]\/$*+.^|[]/\\&/g')
    local OS=$(uname -snrv | sed -e 's/[]\/$+*.^()|[]/\\&/g')
    local INFOS_REGEX=""
    local OLD_CAPINFOS=0

    if [[ "$(capinfos --help)" == *"Capinfos (Wireshark) 2."* ]]; then
        OLD_CAPINFOS=1
    fi

    INFOS_REGEX+="(File type:           Wireshark\/\.\.\. - pcapng.*"
    INFOS_REGEX+="Capture hardware:    $HW.*"
    INFOS_REGEX+="Capture oper-sys:    $OS.*"
    INFOS_REGEX+="Capture application: xdpdump v[0-9]+\.[0-9]+\.[0-9]+.*"
    INFOS_REGEX+="Capture comment:     Capture was taken on interface xdptest, with the following XDP programs loaded:   xdp_dispatcher\(\)     xdp_test_prog_w.*"
    INFOS_REGEX+="Interface #0 info:.*"
    INFOS_REGEX+="Name = ${NS}:xdp_dispatcher\(\)@fentry.*"
    if [ $OLD_CAPINFOS -eq 0 ]; then
        INFOS_REGEX+="Hardware = driver: \"veth\", version: \"1\.0\", fw-version: \"\", rom-version: \"\", bus-info: \"\".*"
    fi
    INFOS_REGEX+="Time precision = nanoseconds \(9\).*"
    INFOS_REGEX+="Interface #1 info:.*"
    INFOS_REGEX+="Name = ${NS}:xdp_dispatcher\(\)@fexit.*"
    if [ $OLD_CAPINFOS -eq 0 ]; then
        INFOS_REGEX+="Hardware = driver: \"veth\", version: \"1\.0\", fw-version: \"\", rom-version: \"\", bus-info: \"\".*"
    fi
    INFOS_REGEX+="Time precision = nanoseconds \(9\))"

    $PING6 -W 2 -c 1 "$INSIDE_IP6" || return 1
    $XDP_LOADER load "$NS" "$TEST_PROG_DIR/test_long_func_name.o" || return 1

    PID=$(start_background "$XDPDUMP -i $NS -w - 2> /dev/null | tcpdump -r - -n")
    $PING6 -W 2 -c 1 "$INSIDE_IP6" || return 1
    RESULT=$(stop_background "$PID")

    if [[ "$RESULT" != *"$PASS_PKT"* ]]; then
        print_result "IPv6 packet not received"
        return 1
    fi

    PID=$(start_background "$XDPDUMP -i $NS -w $PCAP_FILE --rx-capture=entry,exit")
    $PING6 -W 2 -c 1 "$INSIDE_IP6" || return 1
    RESULT=$(stop_background "$PID") || (print_result "xdpdump failed"; return 1)

    RESULT=$(capinfos "$PCAP_FILE") || (print_result "capinfos failed"; return 1)
    if ! [[ $RESULT =~ $INFOS_REGEX ]]; then
        echo "REGEX: $INFOS_REGEX"
        print_result "Failed capinfos content"
        return 1
    fi

    #
    # TODO: We can not yet check the epb_packetid, epb_queue and epb_verdict
    #       fields. When they are implemented by WireShark we can add a test
    #       case here. A hack/patch is available here:
    #         https://github.com/chaudron/wireshark/tree/dev/pcapng_epb_options
    #

    rm "$PCAP_FILE" >& /dev/null

    $XDP_LOADER unload "$NS" --all || return 1
}


test_capt_term()
{
    local PASS_REGEX="(xdp_dispatcher\(\)@entry: packet size 118 bytes on if_index [0-9]+, rx queue [0-9]+, id [0-9]+)"
    local PASS_X_REGEX="(xdp_dispatcher\(\)@entry: packet size 118 bytes, captured 118 bytes on if_index [0-9]+, rx queue [0-9]+, id [0-9]+)"
    local PASS_X_OPT="0x0020:  00 00 00 00 00 02 fc 42 de ad ca fe 00 01 00 00"

    $PING6 -W 2 -c 1 "$INSIDE_IP6" || return 1

    $XDP_LOADER load "$NS" "$TEST_PROG_DIR/test_long_func_name.o" || return 1

    PID=$(start_background "$XDPDUMP -i $NS")
    $PING6 -W 2 -c 1 "$INSIDE_IP6" || return 1
    RESULT=$(stop_background "$PID")

    if ! [[ $RESULT =~ $PASS_REGEX ]]; then
        print_result "IPv6 packet not received"
        return 1
    fi

    PID=$(start_background "$XDPDUMP -i $NS -x")
    $PING6 -W 2 -c 1 "$INSIDE_IP6" || return 1
    RESULT=$(stop_background "$PID")

    if ! [[ $RESULT =~ $PASS_X_REGEX ]]; then
        print_result "IPv6 packet not received[2]"
        return 1
    fi

    # If the IP6 addresses remain the same this simple string compare can be
    # used to verify the -x output is present.
    if [[ "$RESULT" != *"$PASS_X_OPT"* ]]; then
        print_result "IPv6 HEX packet not received"
        return 1
    fi

    $XDP_LOADER unload "$NS" --all || return 1
}

test_exitentry()
{
    local PASS_ENTRY_REGEX="(xdp_dispatcher\(\)@entry: packet size 118 bytes on if_index [0-9]+, rx queue [0-9]+, id [0-9]+)"
    local PASS_EXIT_REGEX="(xdp_dispatcher\(\)@exit\[PASS\]: packet size 118 bytes on if_index [0-9]+, rx queue [0-9]+, id [0-9]+)"
    local PASS_EXIT_D_REGEX="(xdp_dispatcher\(\)@exit\[DROP\]: packet size 118 bytes on if_index [0-9]+, rx queue [0-9]+, id [0-9]+)"
    local ID_ENTRY_REGEX="xdp_dispatcher\(\)@entry: packet size 118 bytes on if_index [0-9]+, rx queue [0-9]+, id ([0-9]+)"
    local ID_EXIT_REGEX="xdp_dispatcher\(\)@exit\[DROP\]: packet size 118 bytes on if_index [0-9]+, rx queue [0-9]+, id ([0-9]+)"

    $XDP_LOADER load "$NS" "$TEST_PROG_DIR/test_long_func_name.o" || return 1

    PID=$(start_background "$XDPDUMP -i $NS --rx-capture=entry")
    $PING6 -W 2 -c 1 "$INSIDE_IP6" || return 1
    RESULT=$(stop_background "$PID")
    if ! [[ $RESULT =~ $PASS_ENTRY_REGEX ]]; then
        print_result "IPv6 entry packet not received"
        return 1
    fi

    PID=$(start_background "$XDPDUMP -i $NS --rx-capture=exit")
    $PING6 -W 2 -c 1 "$INSIDE_IP6" || return 1
    RESULT=$(stop_background "$PID")
    if ! [[ $RESULT =~ $PASS_EXIT_REGEX ]]; then
        print_result "IPv6 exit packet not received"
        return 1
    fi

    $XDP_LOADER unload "$NS" --all || return 1
    $XDP_LOADER load "$NS" "$TEST_PROG_DIR/xdp_drop.o" || return 1

    PID=$(start_background "$XDPDUMP -i $NS --rx-capture=exit")
    $PING6 -W 1 -c 1 "$INSIDE_IP6" # Note that this ping will fail!!
    RESULT=$(stop_background "$PID")
    if ! [[ $RESULT =~ $PASS_EXIT_D_REGEX ]]; then
        print_result "IPv6 drop exit packet not received"
        return 1
    fi

    PID=$(start_background "$XDPDUMP -i $NS --rx-capture=exit,entry")
    $PING6 -W 1 -c 1 "$INSIDE_IP6" # Note that this ping will fail!!
    RESULT=$(stop_background "$PID")
    if ! [[ $RESULT =~ $PASS_EXIT_D_REGEX && $RESULT =~ $PASS_ENTRY_REGEX ]]; then
        print_result "IPv6 drop entry/exit packet not received"
        return 1
    fi

    [[ $RESULT =~ $ID_ENTRY_REGEX ]]
    ENTRY_ID=${BASH_REMATCH[1]}
    [[ $RESULT =~ $ID_EXIT_REGEX ]]
    EXIT_ID=${BASH_REMATCH[1]}
    if [[ "$EXIT_ID" != "$ENTRY_ID" ]]; then
        print_result "Failed matching IDs"
        return 1
    fi

    $XDP_LOADER unload "$NS" --all || return 1
}

test_snap()
{
    local PASS_REGEX="(xdp_dispatcher\(\)@entry: packet size 118 bytes, captured 16 bytes on if_index [0-9]+, rx queue [0-9]+, id [0-9]+)"
    local PASS_II_REGEX="(xdp_dispatcher\(\)@entry: packet size 118 bytes, captured 21 bytes on if_index [0-9]+, rx queue [0-9]+, id [0-9]+)"

    $XDP_LOADER load "$NS" "$TEST_PROG_DIR/test_long_func_name.o" || return 1

    PID=$(start_background "$XDPDUMP -i $NS -x --snapshot-length=16")
    $PING6 -W 2 -c 1 "$INSIDE_IP6" || return 1
    RESULT=$(stop_background "$PID")

    if ! [[ $RESULT =~ $PASS_REGEX ]]; then
        print_result "IPv6 packet fragment not received"
        return 1
    fi

    PID=$(start_background "$XDPDUMP -i $NS -x -s 21")
    $PING6 -W 2 -c 1 "$INSIDE_IP6" || return 1
    RESULT=$(stop_background "$PID")

    if ! [[ $RESULT =~ $PASS_II_REGEX ]]; then
        print_result "IPv6 packet fragment not received[2]"
        return 1
    fi

    $XDP_LOADER unload "$NS" --all || return 1
}

test_multi_pkt()
{
    local PASS_ENTRY_REGEX="(xdp_dispatcher\(\)@entry: packet size [0-9]+ bytes on if_index [0-9]+, rx queue [0-9]+, id 20000)"
    local PASS_EXIT_REGEX="(xdp_dispatcher\(\)@exit\[PASS\]: packet size [0-9]+ bytes on if_index [0-9]+, rx queue [0-9]+, id 20000)"
    local PKT_SIZES=(56 512 1500)

    $XDP_LOADER load "$NS" "$TEST_PROG_DIR/test_long_func_name.o" || return 1

    for PKT_SIZE in "${PKT_SIZES[@]}" ; do

        PID=$(start_background_no_stderr "$XDPDUMP -i $NS --rx-capture=entry,exit")
        timeout 4 $PING6 -W 2 -s "$PKT_SIZE" -c 20000 -f "$INSIDE_IP6" || return 1
        RESULT=$(stop_background "$PID")
        if ! [[ $RESULT =~ $PASS_ENTRY_REGEX ]]; then
            print_result "IPv6 entry packet not received, $PKT_SIZE"
            return 1
        fi

        if ! [[ $RESULT =~ $PASS_EXIT_REGEX ]]; then
            print_result "IPv6 exit packet not received, $PKT_SIZE"
            return 1
        fi
    done

    $XDP_LOADER unload "$NS" --all || return 1
}

test_perf_wakeup()
{
    $XDPDUMP --help | grep -q "\-\-perf-wakeup"
    if [ $? -eq 1 ]; then
        # No support for perf_wakeup, so return SKIP
        return "$SKIPPED_TEST"
    fi

    local PASS_REGEX="(xdp_dispatcher\(\)@entry: packet size 118 bytes on if_index [0-9]+, rx queue [0-9]+)"
    local PASS_10K_REGEX="(xdp_dispatcher\(\)@entry: packet size 118 bytes on if_index [0-9]+, rx queue [0-9]+, id 10000)"
    local WAKEUPS=(0 1 32 128)

    $XDP_LOADER load "$NS" "$TEST_PROG_DIR/test_long_func_name.o" || return 1

    for WAKEUP in "${WAKEUPS[@]}" ; do

        # We send a single packet to make sure flushing of the buffer works!
        PID=$(start_background_no_stderr "$XDPDUMP -i $NS --perf-wakeup=$WAKEUP")
        $PING6 -W 2 -c 1 "$INSIDE_IP6" || return 1
        RESULT=$(stop_background "$PID")

        if ! [[ $RESULT =~ $PASS_REGEX ]]; then
            print_result "IPv6 packet not received for wakeup $WAKEUP"
            return 1
        fi

        # We sent 10k packets and see if the all arrive
        PID=$(start_background_no_stderr "$XDPDUMP -i $NS --perf-wakeup=$WAKEUP")
        timeout 2 $PING6 -W 2 -c 10000 -f  "$INSIDE_IP6" || return 1
        RESULT=$(stop_background "$PID")
        if ! [[ $RESULT =~ $PASS_10K_REGEX ]]; then
            print_result "IPv6 10k packet not received for wakeup $WAKEUP"
            return 1
        fi
    done

    $XDP_LOADER unload "$NS" --all || return 1
}

test_none_xdp()
{
    local PASS_PKT="packet size 118 bytes on if_name \"$NS\""
    local WARN_MSG="WARNING: Specified interface does not have an XDP program loaded, capturing"

    $XDP_LOADER unload "$NS" --all

    PID=$(start_background "$XDPDUMP -i $NS")
    $PING6 -W 2 -c 4 "$INSIDE_IP6" || return 1
    RESULT=$(stop_background "$PID")
    if [[ "$RESULT" != *"$PASS_PKT"* ]]; then
        print_result "IPv6 packet not received"
        return 1
    fi
    if [[ "$RESULT" != *"$WARN_MSG"* ]]; then
        print_result "Missing warning message"
        return 1
    fi
}

test_promiscuous()
{
    local PASS_PKT="packet size 118 bytes on if_name \"$NS\""
    local PASS_REGEX="(xdp_dispatcher\(\)@entry: packet size 118 bytes, captured 118 bytes on if_index [0-9]+, rx queue [0-9]+, id [0-9]+)"

    $XDP_LOADER unload "$NS" --all
    dmesg -C

    PID=$(start_background "$XDPDUMP -i $NS -P")
    $PING6 -W 2 -c 4 "$INSIDE_IP6" || return 1
    RESULT=$(stop_background "$PID")
    if [[ "$RESULT" != *"$PASS_PKT"* ]]; then
        print_result "IPv6 packet not received [legacy mode]"
        return 1
    fi

    RESULT=$(dmesg)
    if [[ "$RESULT" != *"device $NS entered promiscuous mode"* ]]; then
        print_result "Failed enabling promiscuous mode on legacy interface"
        return 1
    fi
    if [[ "$RESULT" != *"device $NS left promiscuous mode"* ]]; then
        print_result "Failed disabling promiscuous mode on legacy interface"
        return 1
    fi

    $XDP_LOADER load "$NS" "$TEST_PROG_DIR/test_long_func_name.o" || return 1
    dmesg -C

    PID=$(start_background "$XDPDUMP -i $NS -x --promiscuous-mode")
    $PING6 -W 2 -c 1 "$INSIDE_IP6" || return 1
    RESULT=$(stop_background "$PID")
    if ! [[ $RESULT =~ $PASS_REGEX ]]; then
        print_result "IPv6 packet not received"
        return 1
    fi

    RESULT=$(dmesg)
    if [[ "$RESULT" != *"device $NS entered promiscuous mode"* ]]; then
        print_result "Failed enabling promiscuous mode on interface"
        return 1
    fi
    if [[ "$RESULT" != *"device $NS left promiscuous mode"* ]]; then
        print_result "Failed disabling promiscuous mode on interface"
        return 1
    fi
}

test_pname_pars()
{
    local PIN_DIR="/sys/fs/bpf/${NS}_PID_$$_$RANDOM"
    local PASS_REGEX="(xdp_test_prog_with_a_long_name\(\)@entry: packet size 118 bytes on if_index [0-9]+, rx queue [0-9]+, id [0-9]+)"

    $PING6 -W 2 -c 1 "$INSIDE_IP6" || return 1

    # Here we load the programs without the xdp-tools loader to make sure
    # they are not loaded as a multi-program.
    bpftool prog loadall "$TEST_PROG_DIR/test_long_func_name.o" "$PIN_DIR"
    bpftool net attach xdpgeneric pinned "$PIN_DIR/xdp_test_prog_long" dev "$NS"

    # We need to specify the function name or else it should fail
    PID=$(start_background "$XDPDUMP -i $NS")
    $PING6 -W 2 -c 1 "$INSIDE_IP6" || return 1
    RESULT=$(stop_background "$PID")
    if [[ $RESULT != *"ERROR: Can't identify the full XDP main function!"* ]]; then
        print_result "xdpdump should fail with duplicate function!"
        rm -rf "$PIN_DIR"
        return 1
    fi

    # Here we specify the correct function name so we should get the packet
    PID=$(start_background "$XDPDUMP -i $NS -p xdp_test_prog_with_a_long_name")
    $PING6 -W 2 -c 1 "$INSIDE_IP6" || return 1
    RESULT=$(stop_background "$PID")
    if ! [[ $RESULT =~ $PASS_REGEX ]]; then
        print_result "IPv6 packet not received"
        rm -rf "$PIN_DIR"
        return 1
    fi

    # Here we specify the wrong correct function name so we should not get the packet
    PID=$(start_background "$XDPDUMP -i $NS -p xdp_test_prog_with_a_long_name_too")
    RESULT=$(stop_background "$PID")
    if [[ $RESULT != *"ERROR: Can't load eBPF object: Kernel verifier blocks program loading"* ]]; then
        print_result "xdpdump should fail being unable to attach!"
        rm -rf "$PIN_DIR"
        return 1
    fi

    # Here we specify an non-existing function
    PID=$(start_background "$XDPDUMP -i $NS -p xdp_test_prog_with_a_long_non_existing_name")
    RESULT=$(stop_background "$PID")
    if [[ $RESULT != *"ERROR: Can't find function 'xdp_test_prog_with_a_long_non_existing_name' on interface!"* ]]; then
        print_result "xdpdump should fail with unknown function!"
        rm -rf "$PIN_DIR"
        return 1
    fi

    # Verify invalid program indexes
    PID=$(start_background "$XDPDUMP -i $NS -p hallo@3e")
    RESULT=$(stop_background "$PID")
    if [[ $RESULT != *"ERROR: Can't extract valid program index from \"hallo@3e\"!"* ]]; then
        print_result "xdpdump should fail with index value error!"
        rm -rf "$PIN_DIR"
        return 1
    fi

    PID=$(start_background "$XDPDUMP -i $NS -p hallo@128")
    RESULT=$(stop_background "$PID")
    if [[ $RESULT != *"ERROR: Invalid program index supplied, \"hallo@128\"!"* ]]; then
        print_result "xdpdump should fail with index out of range!"
        rm -rf "$PIN_DIR"
        return 1
    fi

    # Remove pinned programs
    rm -rf "$PIN_DIR"
    ip link set dev "$NS" xdpgeneric off

    # Now test actual multi-program parsing (negative test cases)
    $XDP_LOADER unload "$NS" --all
    $XDP_LOADER load "$NS" "$TEST_PROG_DIR/test_long_func_name.o" "$TEST_PROG_DIR/xdp_pass.o" "$TEST_PROG_DIR/xdp_drop.o"

    PID=$(start_background "$XDPDUMP -i $NS -p all")
    RESULT=$(stop_background "$PID")
    if [[ $RESULT != *"ERROR: Can't identify the full XDP 'xdp_test_prog_w' function in program 1!"* &&
          $RESULT != *"xdp_test_prog_with_a_long_name@1\n"* &&
          $RESULT != *"xdp_test_prog_with_a_long_name_too@1\n"* &&
          $RESULT != *"Command line to replace 'all':"* &&
          $RESULT != *"  xdp_dispatcher@0,<function_name>@1,xdp_pass@2,xdp_drop@3"* ]]; then
        print_result "xdpdump should fail with all list!"
        return 1
    fi

    PID=$(start_background "$XDPDUMP -i $NS -p hallo@1")
    RESULT=$(stop_background "$PID")
    if [[ $RESULT != *"ERROR: Can't find function 'hallo' in interface program 1!"* ]]; then
        print_result "xdpdump should fail with hallo not found on program 1!"
        return 1
    fi

    PID=$(start_background "$XDPDUMP -i $NS -p hallo")
    RESULT=$(stop_background "$PID")
    if [[ $RESULT != *"ERROR: Can't find function 'hallo' on interface"* ]]; then
        print_result "xdpdump should fail hallo not found!"
        return 1
    fi

    PID=$(start_background "$XDPDUMP -i $NS -p xdp_test_prog_w")
    RESULT=$(stop_background "$PID")
    if [[ $RESULT != *"ERROR: Can't identify the full XDP 'xdp_test_prog_w' function!"* &&
          $RESULT != *"xdp_test_prog_with_a_long_name_too\n"* ]]; then
        print_result "xdpdump should fail can't id xdp_test_prog_w!"
        return 1
    fi

    PID=$(start_background "$XDPDUMP -i $NS -p xdp_test_prog_w@1")
    RESULT=$(stop_background "$PID")
    if [[ $RESULT != *"ERROR: Can't identify the full XDP 'xdp_test_prog_w' function in program 1!"* &&
          $RESULT != *"xdp_test_prog_with_a_long_name_too@1\n"* ]]; then
        print_result "xdpdump should fail can't id xdp_test_prog_w@1!"
        return 1
    fi

    # Now load XDP programs with duplicate functions
    $XDP_LOADER unload "$NS" --all
    $XDP_LOADER load "$NS" "$TEST_PROG_DIR/test_long_func_name.o" "$TEST_PROG_DIR/test_long_func_name.o" "$TEST_PROG_DIR/xdp_pass.o" "$TEST_PROG_DIR/xdp_drop.o"

    PID=$(start_background "$XDPDUMP -i $NS -p xdp_test_prog_with_a_long_name")
    RESULT=$(stop_background "$PID")
    if [[ $RESULT != *"ERROR: The function 'xdp_test_prog_with_a_long_name' exists in multiple programs!"* &&
          $RESULT != *"xdp_test_prog_with_a_long_name@1\n"* &&
          $RESULT != *"xdp_test_prog_with_a_long_name@2\n"* ]]; then
        print_result "xdpdump should fail with duplicate function!"
        return 1
    fi

    $XDP_LOADER unload "$NS" --all
    return 0
}

cleanup_tests()
{
    $XDP_LOADER unload "$NS" --all >/dev/null 2>&1
}
