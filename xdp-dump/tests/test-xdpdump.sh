#
# Test scrip to do basic xdpdump checks
#
# shellcheck disable=2039
#
ALL_TESTS="test_help test_interfaces test_capt_pcap test_capt_pcapng test_capt_term test_exitentry test_snap test_multi_pkt test_perf_wakeup test_promiscuous_selfload test_promiscuous_preload test_none_xdp test_pname_parse test_multi_prog test_xdp_load"

XDPDUMP=${XDPDUMP:-./xdpdump}
XDP_LOADER=${XDP_LOADER:-../xdp-loader/xdp-loader}

RESULT=""

print_result()
{
    if [ -n "$1" ]; then
        echo "ERROR: $1"
        echo "==== RESULT: ===="
        echo "$RESULT"
        echo "==== END ===="
    else
        echo "$RESULT"
    fi
}

test_help()
{
    local XDPDUMP_HELP_TEXT
    XDPDUMP_HELP_TEXT=$(cat <<-END

Usage: xdpdump [options]

 XDPDump tool to dump network traffic

Options:
     --rx-capture <mode>          Capture point for the rx direction (valid values: entry,exit)
 -D, --list-interfaces            Print the list of available interfaces
     --load-xdp-mode <mode>       Mode used for --load-xdp-mode, default native (valid values: native,skb,hw,unspecified)
     --load-xdp-program           Load XDP trace program if no XDP program is loaded
 -i, --interface <ifname>         Name of interface to capture on
     --perf-wakeup <events>       Wake up xdpdump every <events> packets
 -p, --program-names <prog>       Specific program to attach to
 -P, --promiscuous-mode           Open interface in promiscuous mode
 -s, --snapshot-length <snaplen>  Minimum bytes of packet to capture
     --use-pcap                   Use legacy pcap format for XDP traces
 -w, --write <file>               Write raw packets to pcap file
 -x, --hex                        Print the full packet in hex
 -v, --verbose                    Enable verbose logging (-vv: more verbose)
     --version                    Display version information
 -h, --help                       Show this help

END
          )

    $XDPDUMP --help | grep -q "\-\-perf-wakeup"
    if [ $? -eq 1 ]; then
        XDPDUMP_HELP_TEXT=$(echo "$XDPDUMP_HELP_TEXT" | sed '/--perf-wakeup <events>/d')
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
    local NO_PROG_REGEX="($NS +<No XDP program loaded!>)"
    if is_multiprog_supported; then
        local PROG_REGEX="($NS[[:space:]]+xdp_dispatcher.+xdp_drop)"
    else
        local PROG_REGEX="($NS[[:space:]]+xdp_drop)"
    fi

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
    skip_if_missing_kernel_symbol bpf_xdp_output_proto
    skip_if_missing_trace_attach

    local PASS_PKT="IP6 $INSIDE_IP6 > $OUTSIDE_IP6: ICMP6, echo reply(, id [0-9]+)?, seq 1, length 64"

    $PING6 -W 2 -c 1 "$INSIDE_IP6" || return 1
    $XDP_LOADER load "$NS" "$TEST_PROG_DIR/test_long_func_name.o" || return 1

    PID=$(start_background "$XDPDUMP -i $NS -p xdp_test_prog_with_a_long_name --use-pcap -w - 2> /dev/null | tcpdump -r - -n")
    $PING6 -W 2 -c 1 "$INSIDE_IP6" || return 1
    sleep 1
    RESULT=$(stop_background "$PID")

    $XDP_LOADER unload "$NS" --all || return 1

    if ! [[ $RESULT =~ $PASS_PKT ]]; then
        print_result "IPv6 packet not received"
        return 1
    fi
}

version_greater_or_equal()
{
    printf '%s\n%s\n' "$2" "$1" | sort -V -C
}

test_capt_pcapng()
{
    skip_if_missing_kernel_symbol bpf_xdp_output_proto
    skip_if_missing_trace_attach

    local PCAP_FILE="/tmp/${NS}_PID_$$_$RANDOM.pcap"
    local PASS_PKT="IP6 $INSIDE_IP6 > $OUTSIDE_IP6: ICMP6, echo reply(, id [0-9]+)?, seq 1, length 64"
    local HW=$(uname -m | sed -e 's/[]\/$*+.^|[]/\\&/g')
    local OS=$(uname -snrv | sed -e 's/[]\/$+*.^()|[]/\\&/g')
    local INFOS_REGEX=""
    local OLD_CAPINFOS=0
    local TSHARK_VERSION=$(tshark --version 2> /dev/null | sed -ne 's/^TShark (Wireshark) \([0-9]\+\.[0-9]\+\.[0-9]\+\).*/\1/p')

    if [[ "$(capinfos --help)" == *"Capinfos (Wireshark) 2."* ]]; then
        OLD_CAPINFOS=1
    fi

    INFOS_REGEX+="(File type:           Wireshark\/\.\.\. - pcapng.*"
    INFOS_REGEX+="Capture hardware:    $HW.*"
    INFOS_REGEX+="Capture oper-sys:    $OS.*"
    INFOS_REGEX+="Capture application: xdpdump v[0-9]+\.[0-9]+\.[0-9]+.*"
    INFOS_REGEX+="Capture comment:     Capture was taken on interface $NS, with the following XDP programs loaded:   xdp_dispatcher\(\)     xdp_test_prog_w.*"
    INFOS_REGEX+="Interface #0 info:.*"
    INFOS_REGEX+="Name = ${NS}:xdp_test_prog_with_a_long_name\(\)@fentry.*"
    if [ $OLD_CAPINFOS -eq 0 ]; then
        INFOS_REGEX+="Hardware = driver: \"veth\", version: \"1\.0\", fw-version: \"\", rom-version: \"\", bus-info: \"\".*"
    fi
    INFOS_REGEX+="Time precision = nanoseconds \(9\).*"
    INFOS_REGEX+="Interface #1 info:.*"
    INFOS_REGEX+="Name = ${NS}:xdp_test_prog_with_a_long_name\(\)@fexit.*"
    if [ $OLD_CAPINFOS -eq 0 ]; then
        INFOS_REGEX+="Hardware = driver: \"veth\", version: \"1\.0\", fw-version: \"\", rom-version: \"\", bus-info: \"\".*"
    fi
    INFOS_REGEX+="Time precision = nanoseconds \(9\))"

    $PING6 -W 2 -c 1 "$INSIDE_IP6" || return 1
    $XDP_LOADER load "$NS" "$TEST_PROG_DIR/test_long_func_name.o" || return 1

    PID=$(start_background "$XDPDUMP -i $NS -p xdp_test_prog_with_a_long_name -w - 2> /dev/null | tcpdump -r - -n")
    $PING6 -W 2 -c 1 "$INSIDE_IP6" || return 1
    RESULT=$(stop_background "$PID")

    if ! [[ $RESULT =~ $PASS_PKT ]]; then
        print_result "IPv6 packet not received"
        return 1
    fi

    PID=$(start_background "$XDPDUMP -i $NS -p xdp_test_prog_with_a_long_name -w $PCAP_FILE --rx-capture=entry,exit")
    $PING6 -W 2 -c 1 "$INSIDE_IP6" || (rm "$PCAP_FILE" >& /dev/null; return 1)
    RESULT=$(stop_background "$PID") || (print_result "xdpdump failed"; rm "$PCAP_FILE" >& /dev/null; return 1)

    RESULT=$(capinfos "$PCAP_FILE") || (print_result "capinfos failed"; rm "$PCAP_FILE" >& /dev/null; return 1)
    if ! [[ $RESULT =~ $INFOS_REGEX ]]; then
        echo "REGEX: $INFOS_REGEX"
        print_result "Failed capinfos content"
	rm "$PCAP_FILE" >& /dev/null
        return 1
    fi

    if version_greater_or_equal "$TSHARK_VERSION" 3.6.7; then
	local ATTRIB_REGEX="^$NS:xdp_test_prog_with_a_long_name\(\)@fentry	0	1	$.*^$NS:xdp_test_prog_with_a_long_name\(\)@fexit	0	1	2$.*"
	RESULT=$(tshark -r "$PCAP_FILE" -T fields \
			-e frame.interface_name \
			-e frame.interface_queue \
			-e frame.packet_id \
			-e frame.verdict.ebpf_xdp)
	if ! [[ $RESULT =~ $ATTRIB_REGEX ]]; then
            print_result "Failed attributes content with Tshark $TSHARK_VERSION"
	    rm "$PCAP_FILE" >& /dev/null
            return 1
	fi
    fi

    rm "$PCAP_FILE" >& /dev/null

    $XDP_LOADER unload "$NS" --all || return 1
}

test_capt_term()
{
    skip_if_missing_kernel_symbol bpf_xdp_output_proto
    skip_if_missing_trace_attach

    local PASS_REGEX="(xdp_test_prog_with_a_long_name\(\)@entry: packet size 118 bytes on if_index [0-9]+, rx queue [0-9]+, id [0-9]+)"
    local PASS_X_REGEX="(xdp_test_prog_with_a_long_name\(\)@entry: packet size 118 bytes, captured 118 bytes on if_index [0-9]+, rx queue [0-9]+, id [0-9]+)"
    local PASS_X_OPT="0x0020:  00 00 00 00 00 02 fc 42 de ad ca fe"

    $PING6 -W 2 -c 1 "$INSIDE_IP6" || return 1

    $XDP_LOADER load "$NS" "$TEST_PROG_DIR/test_long_func_name.o" || return 1

    PID=$(start_background "$XDPDUMP -i $NS -p xdp_test_prog_with_a_long_name")
    $PING6 -W 2 -c 1 "$INSIDE_IP6" || return 1
    RESULT=$(stop_background "$PID")

    if ! [[ $RESULT =~ $PASS_REGEX ]]; then
        print_result "IPv6 packet not received"
        return 1
    fi

    PID=$(start_background "$XDPDUMP -i $NS -p xdp_test_prog_with_a_long_name -x")
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
    skip_if_missing_kernel_symbol bpf_xdp_output_proto
    skip_if_missing_trace_attach

    local PASS_ENTRY_REGEX="(xdp_test_prog_with_a_long_name\(\)@entry: packet size 118 bytes on if_index [0-9]+, rx queue [0-9]+, id [0-9]+)"
    local PASS_EXIT_REGEX="(xdp_test_prog_with_a_long_name\(\)@exit\[PASS\]: packet size 118 bytes on if_index [0-9]+, rx queue [0-9]+, id [0-9]+)"
    local PASS_ENTRY_D_REGEX="(xdp_drop\(\)@entry: packet size 118 bytes on if_index [0-9]+, rx queue [0-9]+, id [0-9]+)"
    local PASS_EXIT_D_REGEX="(xdp_drop\(\)@exit\[DROP\]: packet size 118 bytes on if_index [0-9]+, rx queue [0-9]+, id [0-9]+)"
    local ID_ENTRY_REGEX="xdp_drop\(\)@entry: packet size 118 bytes on if_index [0-9]+, rx queue [0-9]+, id ([0-9]+)"
    local ID_EXIT_REGEX="xdp_drop\(\)@exit\[DROP\]: packet size 118 bytes on if_index [0-9]+, rx queue [0-9]+, id ([0-9]+)"

    $XDP_LOADER load "$NS" "$TEST_PROG_DIR/test_long_func_name.o" || return 1

    PID=$(start_background "$XDPDUMP -i $NS -p xdp_test_prog_with_a_long_name --rx-capture=entry")
    $PING6 -W 2 -c 1 "$INSIDE_IP6" || return 1
    RESULT=$(stop_background "$PID")
    if ! [[ $RESULT =~ $PASS_ENTRY_REGEX ]]; then
        print_result "IPv6 entry packet not received"
        return 1
    fi

    PID=$(start_background "$XDPDUMP -i $NS -p xdp_test_prog_with_a_long_name --rx-capture=exit")
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
    if ! [[ $RESULT =~ $PASS_EXIT_D_REGEX && $RESULT =~ $PASS_ENTRY_D_REGEX ]]; then
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
    skip_if_missing_kernel_symbol bpf_xdp_output_proto
    skip_if_missing_trace_attach

    local PASS_REGEX="(xdp_test_prog_with_a_long_name\(\)@entry: packet size 118 bytes, captured 16 bytes on if_index [0-9]+, rx queue [0-9]+, id [0-9]+)"
    local PASS_II_REGEX="(xdp_test_prog_with_a_long_name\(\)@entry: packet size 118 bytes, captured 21 bytes on if_index [0-9]+, rx queue [0-9]+, id [0-9]+)"

    $XDP_LOADER load "$NS" "$TEST_PROG_DIR/test_long_func_name.o" || return 1

    PID=$(start_background "$XDPDUMP -i $NS -p xdp_test_prog_with_a_long_name -x --snapshot-length=16")
    $PING6 -W 2 -c 1 "$INSIDE_IP6" || return 1
    RESULT=$(stop_background "$PID")

    if ! [[ $RESULT =~ $PASS_REGEX ]]; then
        print_result "IPv6 packet fragment not received"
        return 1
    fi

    PID=$(start_background "$XDPDUMP -i $NS -p xdp_test_prog_with_a_long_name -x -s 21")
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
    skip_if_missing_kernel_symbol bpf_xdp_output_proto
    skip_if_missing_trace_attach

    local PASS_ENTRY_REGEX="(xdp_test_prog_with_a_long_name\(\)@entry: packet size [0-9]+ bytes on if_index [0-9]+, rx queue [0-9]+, id 20000)"
    local PASS_EXIT_REGEX="(xdp_test_prog_with_a_long_name\(\)@exit\[PASS\]: packet size [0-9]+ bytes on if_index [0-9]+, rx queue [0-9]+, id 20000)"
    local PKT_SIZES=(56 512 1500)

    $XDP_LOADER load "$NS" "$TEST_PROG_DIR/test_long_func_name.o" || return 1

    for PKT_SIZE in "${PKT_SIZES[@]}" ; do

        PID=$(start_background_no_stderr "$XDPDUMP -i $NS -p xdp_test_prog_with_a_long_name --rx-capture=entry,exit")
        timeout 40 $PING6 -q -W 2 -s "$PKT_SIZE" -c 20000 -f "$INSIDE_IP6" || return 1
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
    skip_if_missing_kernel_symbol bpf_xdp_output_proto
    skip_if_missing_trace_attach

    $XDPDUMP --help | grep -q "\-\-perf-wakeup"
    if [ $? -eq 1 ]; then
        # No support for perf_wakeup, so return SKIP
        return "$SKIPPED_TEST"
    fi

    local PASS_REGEX="(xdp_test_prog_with_a_long_name\(\)@entry: packet size 118 bytes on if_index [0-9]+, rx queue [0-9]+)"
    local PASS_10K_REGEX="(xdp_test_prog_with_a_long_name\(\)@entry: packet size 118 bytes on if_index [0-9]+, rx queue [0-9]+, id 10000)"
    local WAKEUPS=(0 1 32 128)

    $XDP_LOADER load "$NS" "$TEST_PROG_DIR/test_long_func_name.o" || return 1

    for WAKEUP in "${WAKEUPS[@]}" ; do

        # We send a single packet to make sure flushing of the buffer works!
        PID=$(start_background_no_stderr "$XDPDUMP -i $NS -p xdp_test_prog_with_a_long_name --perf-wakeup=$WAKEUP")
        $PING6 -W 2 -c 1 "$INSIDE_IP6" || return 1
        RESULT=$(stop_background "$PID")

        if ! [[ $RESULT =~ $PASS_REGEX ]]; then
            print_result "IPv6 packet not received for wakeup $WAKEUP"
            return 1
        fi

        # We sent 10k packets and see if the all arrive
        PID=$(start_background_no_stderr "$XDPDUMP -i $NS -p xdp_test_prog_with_a_long_name --perf-wakeup=$WAKEUP")
        timeout 20 "$PING6" -q -W 2 -c 10000 -f  "$INSIDE_IP6" || return 1
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
    local WARN_MSG="WARNING: Specified interface does not have an XDP program loaded,"

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

test_promiscuous_selfload()
{
    local PASS_PKT="packet size 118 bytes on if_name \"$NS\""
    local PASS_REGEX="(xdp_test_prog_with_a_long_name\(\)@entry: packet size 118 bytes, captured 118 bytes on if_index [0-9]+, rx queue [0-9]+, id [0-9]+)"

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
    if [[ "$RESULT" != *"device $NS entered promiscuous mode"* ]] && [[ "$RESULT" != *"$NS: entered promiscuous mode"* ]]; then
        print_result "Failed enabling promiscuous mode on legacy interface"
        return 1
    fi
    if [[ "$RESULT" != *"device $NS left promiscuous mode"* ]] && [[ "$RESULT" != *"$NS: left promiscuous mode"* ]]; then
        print_result "Failed disabling promiscuous mode on legacy interface"
        return 1
    fi
}

test_promiscuous_preload()
{
    skip_if_missing_kernel_symbol bpf_xdp_output
    skip_if_missing_trace_attach

    local PASS_REGEX="(xdp_test_prog_with_a_long_name\(\)@entry: packet size 118 bytes, captured 118 bytes on if_index [0-9]+, rx queue [0-9]+, id [0-9]+)"

    $XDP_LOADER load "$NS" "$TEST_PROG_DIR/test_long_func_name.o" || return 1
    dmesg -C

    PID=$(start_background "$XDPDUMP -i $NS -p xdp_test_prog_with_a_long_name -x --promiscuous-mode")
    $PING6 -W 2 -c 1 "$INSIDE_IP6" || return 1
    RESULT=$(stop_background "$PID")
    if ! [[ $RESULT =~ $PASS_REGEX ]]; then
        print_result "IPv6 packet not received"
        return 1
    fi

    RESULT=$(dmesg)
    if [[ "$RESULT" != *"device $NS entered promiscuous mode"* ]] && [[ "$RESULT" != *"$NS: entered promiscuous mode"* ]]; then
        print_result "Failed enabling promiscuous mode on interface"
        return 1
    fi
    if [[ "$RESULT" != *"device $NS left promiscuous mode"* ]] && [[ "$RESULT" != *"$NS: left promiscuous mode"* ]]; then
        print_result "Failed disabling promiscuous mode on interface"
        return 1
    fi
}

test_pname_parse()
{
    skip_if_legacy_fallback

    local PASS_REGEX="(xdp_test_prog_with_a_long_name\(\)@entry: packet size 118 bytes on if_index [0-9]+, rx queue [0-9]+, id [0-9]+)"
    local PROG_ID_1=0
    local PROG_ID_2=0
    local PROG_ID_3=0
    local PROG_ID_4=0

    $PING6 -W 2 -c 1 "$INSIDE_IP6" || return 1

    # Here we load the programs without the xdp-tools loader to make sure
    # they are not loaded as a multi-program.
    $TEST_PROG_DIR/test-tool load -m skb "$NS" "$TEST_PROG_DIR/test_long_func_name.o"

    # We need to specify the function name or else it should fail
    PID=$(start_background "$XDPDUMP -i $NS")
    $PING6 -W 2 -c 1 "$INSIDE_IP6" || return 1
    RESULT=$(stop_background "$PID")
    if [[ $RESULT != *"ERROR: Can't identify the full XDP main function!"* ]]; then
        print_result "xdpdump should fail with duplicate function!"
        return 1
    fi

    # Here we specify the correct function name so we should get the packet
    PID=$(start_background "$XDPDUMP -i $NS -p xdp_test_prog_with_a_long_name")
    $PING6 -W 2 -c 1 "$INSIDE_IP6" || return 1
    RESULT=$(stop_background "$PID")
    if ! [[ $RESULT =~ $PASS_REGEX ]]; then
        print_result "IPv6 packet not received"
        return 1
    fi

    # Here we specify the wrong correct function name so we should not get the packet
    PID=$(start_background "$XDPDUMP -i $NS -p xdp_test_prog_with_a_long_name_too")
    RESULT=$(stop_background "$PID")
    if [[ $RESULT != *"ERROR: Can't load eBPF object:"* ]]; then
        print_result "xdpdump should fail being unable to attach!"
        return 1
    fi

    # Here we specify an non-existing function
    PID=$(start_background "$XDPDUMP -i $NS -p xdp_test_prog_with_a_long_non_existing_name")
    RESULT=$(stop_background "$PID")
    if [[ $RESULT != *"ERROR: Can't find function 'xdp_test_prog_with_a_long_non_existing_name' on interface!"* ]]; then
        print_result "xdpdump should fail with unknown function!"
        return 1
    fi

    # Verify invalid program indexes
    PID=$(start_background "$XDPDUMP -i $NS -p hallo@3e")
    RESULT=$(stop_background "$PID")
    if [[ $RESULT != *"ERROR: Can't extract valid program id from \"hallo@3e\"!"* ]]; then
        print_result "xdpdump should fail with id value error!"
        return 1
    fi

    PID=$(start_background "$XDPDUMP -i $NS -p hallo@128")
    RESULT=$(stop_background "$PID")
    if [[ $RESULT != *"ERROR: Invalid program id supplied, \"hallo@128\"!"* ]]; then
        print_result "xdpdump should fail with invalid id!"
        return 1
    fi

    # Remove loaded program
    ip link set dev "$NS" xdpgeneric off

    # Now test actual multi-program parsing (negative test cases)
    $XDP_LOADER unload "$NS" --all
    $XDP_LOADER load "$NS" "$TEST_PROG_DIR/test_long_func_name.o" "$TEST_PROG_DIR/xdp_pass.o" "$TEST_PROG_DIR/xdp_drop.o"

    PID=$(start_background "$XDPDUMP -D")
    RESULT=$(stop_background "$PID")
    PROG_ID_1=$(echo "$RESULT" | grep "$NS" -A4 | cut -c51-55 | sed -n 1p | tr -d ' ')
    PROG_ID_2=$(echo "$RESULT" | grep "$NS" -A4 | cut -c51-55 | sed -n 2p | tr -d ' ')
    PROG_ID_3=$(echo "$RESULT" | grep "$NS" -A4 | cut -c51-55 | sed -n 3p | tr -d ' ')
    PROG_ID_4=$(echo "$RESULT" | grep "$NS" -A4 | cut -c51-55 | sed -n 4p | tr -d ' ')

    PID=$(start_background "$XDPDUMP -i $NS -p all")
    RESULT=$(stop_background "$PID")
    if [[ $RESULT != *"ERROR: Can't identify the full XDP 'xdp_test_prog_w' function in program $PROG_ID_2!"* ||
          $RESULT != *"xdp_test_prog_with_a_long_name@$PROG_ID_2"* ||
          $RESULT != *"xdp_test_prog_with_a_long_name_too@$PROG_ID_2"* ||
          $RESULT != *"Command line to replace 'all':"* ||
          $RESULT != *"xdp_dispatcher@$PROG_ID_1,<function_name>@$PROG_ID_2,xdp_pass@$PROG_ID_3,xdp_drop@$PROG_ID_4"* ]]; then
        print_result "xdpdump should fail with all list!"
        return 1
    fi

    PID=$(start_background "$XDPDUMP -i $NS -p hallo@$PROG_ID_1")
    RESULT=$(stop_background "$PID")
    if [[ $RESULT != *"ERROR: Can't find function 'hallo' in interface program $PROG_ID_1!"* ]]; then
        print_result "xdpdump should fail with hallo not found on program $PROG_ID_1!"
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
    if [[ $RESULT != *"ERROR: Can't identify the full XDP 'xdp_test_prog_w' function!"* ||
          $RESULT != *"xdp_test_prog_with_a_long_name_too"* ]]; then
        print_result "xdpdump should fail can't id xdp_test_prog_w!"
        return 1
    fi

    PID=$(start_background "$XDPDUMP -i $NS -p xdp_test_prog_w@$PROG_ID_2")
    RESULT=$(stop_background "$PID")
    if [[ $RESULT != *"ERROR: Can't identify the full XDP 'xdp_test_prog_w' function in program $PROG_ID_2!"* ||
          $RESULT != *"xdp_test_prog_with_a_long_name_too@$PROG_ID_2"* ]]; then
        print_result "xdpdump should fail can't id xdp_test_prog_w@$PROG_ID_2!"
        return 1
    fi

    # Now load XDP programs with duplicate functions
    $XDP_LOADER unload "$NS" --all
    $XDP_LOADER load "$NS" "$TEST_PROG_DIR/test_long_func_name.o" "$TEST_PROG_DIR/test_long_func_name.o" "$TEST_PROG_DIR/xdp_pass.o" "$TEST_PROG_DIR/xdp_drop.o"

    PID=$(start_background "$XDPDUMP -D")
    RESULT=$(stop_background "$PID")
    PROG_ID_1=$(echo "$RESULT" | grep "$NS" -A2 | cut -c51-55 | sed -n 1p | tr -d ' ')
    PROG_ID_2=$(echo "$RESULT" | grep "$NS" -A2 | cut -c51-55 | sed -n 2p | tr -d ' ')
    PROG_ID_3=$(echo "$RESULT" | grep "$NS" -A2 | cut -c51-55 | sed -n 2p | tr -d ' ')

    PID=$(start_background "$XDPDUMP -i $NS -p xdp_test_prog_with_a_long_name")
    RESULT=$(stop_background "$PID")
    if [[ $RESULT != *"ERROR: The function 'xdp_test_prog_with_a_long_name' exists in multiple programs!"* ||
          $RESULT != *"xdp_test_prog_with_a_long_name@$PROG_ID_2"* ||
          $RESULT != *"xdp_test_prog_with_a_long_name@$PROG_ID_3"* ]]; then
        print_result "xdpdump should fail with duplicate function!"
        return 1
    fi

    $XDP_LOADER unload "$NS" --all
    return 0
}

test_multi_prog()
{
    skip_if_legacy_fallback
    skip_if_missing_trace_attach

    local ENTRY_REGEX="(xdp_dispatcher\(\)@entry: packet size 118 bytes on if_index [0-9]+, rx queue [0-9]+, id [0-9]+).*(xdp_pass\(\)@entry: packet size 118 bytes on if_index [0-9]+, rx queue [0-9]+, id [0-9]+)"
    local EXIT_REGEX="(xdp_pass\(\)@exit\[PASS\]: packet size 118 bytes on if_index [0-9]+, rx queue [0-9]+, id [0-9]+).*(xdp_dispatcher\(\)@exit\[PASS\]: packet size 118 bytes on if_index [0-9]+, rx queue [0-9]+, id [0-9]+)"
    local PROG_ID_1=0
    local PROG_ID_4=0

    $XDP_LOADER load "$NS" "$TEST_PROG_DIR/xdp_pass.o" "$TEST_PROG_DIR/test_long_func_name.o" "$TEST_PROG_DIR/xdp_pass.o"

    PID=$(start_background "$XDPDUMP -D")
    RESULT=$(stop_background "$PID")
    PROG_ID_1=$(echo "$RESULT" | grep "$NS" -A4 | cut -c51-55 | sed -n 1p | tr -d ' ')
    PROG_ID_4=$(echo "$RESULT" | grep "$NS" -A4 | cut -c51-55 | sed -n 4p | tr -d ' ')

    PID=$(start_background "$XDPDUMP -i $NS -p xdp_dispatcher,xdp_pass@$PROG_ID_4 -vv")
    $PING6 -W 2 -c 1 "$INSIDE_IP6" || return 1
    RESULT=$(stop_background "$PID")
    if [[ $RESULT == *"Unrecognized arg#0 type PTR"* ]]; then
	$XDP_LOADER unload "$NS" --all
	return $SKIPPED_TEST
    fi
    if ! [[ $RESULT =~ $ENTRY_REGEX ]]; then
        print_result "Not received all fentry packets"
        return 1
    fi

    PID=$(start_background "$XDPDUMP -i $NS -p xdp_dispatcher,xdp_pass@$PROG_ID_4 --rx-capture=exit")
    $PING6 -W 2 -c 1 "$INSIDE_IP6" || return 1
    RESULT=$(stop_background "$PID")
    if ! [[ $RESULT =~ $EXIT_REGEX ]]; then
        print_result "Not received all fexit packets"
        return 1
    fi

    PID=$(start_background "$XDPDUMP -i $NS -p xdp_dispatcher,xdp_pass@$PROG_ID_4 --rx-capture=exit,entry")
    $PING6 -W 2 -c 1 "$INSIDE_IP6" || return 1
    RESULT=$(stop_background "$PID")
    if ! [[ $RESULT =~ $ENTRY_REGEX ]]; then
        print_result "Not received all fentry packets on entry/exit test"
        return 1
    fi
    if ! [[ $RESULT =~ $EXIT_REGEX ]]; then
        print_result "Not received all fexit packets on entry/exit test"
        return 1
    fi

    PID=$(start_background "$XDPDUMP -i $NS -p $PROG_ID_1,$PROG_ID_4 --rx-capture=exit,entry")
    $PING6 -W 2 -c 1 "$INSIDE_IP6" || return 1
    RESULT=$(stop_background "$PID")
    if ! [[ $RESULT =~ $ENTRY_REGEX ]]; then
        print_result "[IDs]Not received all fentry packets on entry/exit test"
        return 1
    fi
    if ! [[ $RESULT =~ $EXIT_REGEX ]]; then
        print_result "[IDs]Not received all fexit packets on entry/exit test"
        return 1
    fi

    PID=$(start_background "$XDPDUMP -i $NS -p xdp_dispatcher,$PROG_ID_4 --rx-capture=exit,entry")
    $PING6 -W 2 -c 1 "$INSIDE_IP6" || return 1
    RESULT=$(stop_background "$PID")
    if ! [[ $RESULT =~ $ENTRY_REGEX ]]; then
        print_result "[Mix]Not received all fentry packets on entry/exit test"
        return 1
    fi
    if ! [[ $RESULT =~ $EXIT_REGEX ]]; then
        print_result "[Mix]Not received all fexit packets on entry/exit test"
        return 1
    fi

    $XDP_LOADER unload "$NS" --all
    return 0
}

test_xdp_load()
{
    local PASS_REGEX="(xdpdump\(\)@entry: packet size 118 bytes on if_index [0-9]+, rx queue [0-9]+, id [0-9]+)"
    local WARN_MSG="Will load a capture only XDP program!"

    PID=$(start_background "$XDPDUMP -i $NS --load-xdp-program")
    $PING6 -W 2 -c 1 "$INSIDE_IP6" || return 1
    RESULT=$(stop_background "$PID")
    if [[ "$RESULT" != *"$WARN_MSG"* ]]; then
        print_result "Missing warning message"
        return 1
    fi
    if ! [[ $RESULT =~ $PASS_REGEX ]]; then
        print_result "IPv6 packet not received"
        return 1
    fi
}

cleanup_tests()
{
    $XDP_LOADER unload "$NS" --all >/dev/null 2>&1
}
