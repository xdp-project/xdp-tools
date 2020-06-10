#
# Test scrip to do basic xdpdump checks
#
# shellcheck disable=2039
#
ALL_TESTS="test_help test_interfaces test_capt_pcap test_capt_pcapng test_capt_term test_exitentry test_snap test_multi_pkt test_perf_wakeup test_none_xdp"

XDPDUMP=./xdpdump
XDP_LOADER=../xdp-loader/xdp-loader

if which ping6 >/dev/null 2>&1; then
    PING6=ping6
else
    PING6=ping
fi

RESULT=""

print_result()
{
    echo "$RESULT"
    if [ -n "$1" ]; then
        echo "ERROR: $1"
    fi
}

start_background()
{
    local TMP_FILE="/tmp/${NS}_PID_$$_$RANDOM"
    eval "${1} >& ${TMP_FILE} &"
    local PID=$!
    sleep 1 # Wait to make sure the command is executed in the background

    mv "$TMP_FILE" "/tmp/${NS}_PID_${PID}" >& /dev/null

    echo "$PID"
}

start_background_no_stderr()
{
    local TMP_FILE="/tmp/${NS}_PID_$$_$RANDOM"
    eval "${1} 1> ${TMP_FILE} 2>/dev/null &"
    local PID=$!
    sleep 1 # Wait to make sure the command is executed in the background

    mv "$TMP_FILE" "/tmp/${NS}_PID_${PID}" >& /dev/null

    echo "$PID"
}

stop_background()
{
    local OUTPUT_FILE="/tmp/${NS}_PID_${1}"
    kill -SIGINT "$1"
    sleep 1 # Wait to make sure the buffer is flushed after the shutdown
    cat "$OUTPUT_FILE"
    rm "$OUTPUT_FILE" >& /dev/null
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
    local HW=$(uname -p | sed -e 's/[]\/$*+.^|[]/\\&/g')
    local OS=$(uname -snrv | sed -e 's/[]\/$+*.^|[]/\\&/g')
    local INFOS_REGEX=""

    INFOS_REGEX+="(File type:           Wireshark\/\.\.\. - pcapng.*"
    INFOS_REGEX+="Capture hardware:    $HW.*"
    INFOS_REGEX+="Capture oper-sys:    $OS.*"
    INFOS_REGEX+="Capture application: xdpdump v[0-9]+\.[0-9]+\.[0-9]+.*"
    INFOS_REGEX+="Interface #0 info:.*"
    INFOS_REGEX+="Name = ${NS}@fentry.*"
    INFOS_REGEX+="Description = ${NS}:xdp_dispatcher\(\)@fentry.*"
    INFOS_REGEX+="Hardware = driver: \"veth\", version: \"1\.0\", fw-version: \"\", rom-version: \"\", bus-info: \"\".*"
    INFOS_REGEX+="Time precision = nanoseconds \(9\).*"
    INFOS_REGEX+="Interface #1 info:.*"
    INFOS_REGEX+="Name = ${NS}@fexit.*"
    INFOS_REGEX+="Description = ${NS}:xdp_dispatcher\(\)@fexit.*"
    INFOS_REGEX+="Hardware = driver: \"veth\", version: \"1\.0\", fw-version: \"\", rom-version: \"\", bus-info: \"\".*"
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
    local PASS_REGEX="(@entry: packet size 118 bytes on if_index [0-9]+, rx queue [0-9]+, id [0-9]+)"
    local PASS_X_REGEX="(@entry: packet size 118 bytes, captured 118 bytes on if_index [0-9]+, rx queue [0-9]+, id [0-9]+)"
    local PASS_X_OPT="0x0020:  00 00 00 00 00 02 fc 00 de ad ca fe 00 01 00 00  ................"

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
    local PASS_ENTRY_REGEX="(@entry: packet size 118 bytes on if_index [0-9]+, rx queue [0-9]+, id [0-9]+)"
    local PASS_EXIT_REGEX="(@exit\[PASS\]: packet size 118 bytes on if_index [0-9]+, rx queue [0-9]+, id [0-9]+)"
    local PASS_EXIT_D_REGEX="(@exit\[DROP\]: packet size 118 bytes on if_index [0-9]+, rx queue [0-9]+, id [0-9]+)"
    local ID_ENTRY_REGEX="@entry: packet size 118 bytes on if_index [0-9]+, rx queue [0-9]+, id ([0-9]+)"
    local ID_EXIT_REGEX="@exit\[DROP\]: packet size 118 bytes on if_index [0-9]+, rx queue [0-9]+, id ([0-9]+)"

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
    $PING6 -W 0.1 -c 1 "$INSIDE_IP6" # Note that this ping will fail!!
    RESULT=$(stop_background "$PID")
    if ! [[ $RESULT =~ $PASS_EXIT_D_REGEX ]]; then
        print_result "IPv6 drop exit packet not received"
        return 1
    fi

    PID=$(start_background "$XDPDUMP -i $NS --rx-capture=exit,entry")
    $PING6 -W 0.1 -c 1 "$INSIDE_IP6" # Note that this ping will fail!!
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
    local PASS_REGEX="(@entry: packet size 118 bytes, captured 16 bytes on if_index [0-9]+, rx queue [0-9]+, id [0-9]+)"
    local PASS_II_REGEX="(@entry: packet size 118 bytes, captured 21 bytes on if_index [0-9]+, rx queue [0-9]+, id [0-9]+)"

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
    local PASS_ENTRY_REGEX="(@entry: packet size [0-9]+ bytes on if_index [0-9]+, rx queue [0-9]+, id 20000)"
    local PASS_EXIT_REGEX="(@exit\[PASS\]: packet size [0-9]+ bytes on if_index [0-9]+, rx queue [0-9]+, id 20000)"
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

    local PASS_REGEX="(@entry: packet size 118 bytes on if_index [0-9]+, rx queue [0-9]+)"
    local PASS_10K_REGEX="(@entry: packet size 118 bytes on if_index [0-9]+, rx queue [0-9]+, id 10000)"
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
    echo "$RESULT"
    if [[ "$RESULT" != *"$PASS_PKT"* ]]; then
        print_result "IPv6 packet not received"
        return 1
    fi
    if [[ "$RESULT" != *"$WARN_MSG"* ]]; then
        print_result "Missing warning message"
        return 1
    fi
}
