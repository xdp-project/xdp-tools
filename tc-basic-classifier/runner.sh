#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
# Copyright 2021 Frey Alfredsson <freysteinn@freysteinn.com>

set -o errexit
set -o nounset

### Configuration
IP="ip"
TC="tc"

# Left and right IPs
L_IP=172.16.16.10
R_IP=172.16.16.20
L_CIDR="${L_IP}/24"
R_CIDR="${R_IP}/24"

LIMIT=100mbit
START_RATE=5mbit
P8080_LIMIT=80mbit
P8081_LIMIT=40mbit
DEFAULT_LIMIT=20mbit

### Constants
L_NS="left"
R_NS="right"
L_DEV="$L_NS-veth"
R_DEV="$R_NS-veth"


### Helper functions
function filter-help() {
	cat <<-EOF
	Usage: [<bpf> | <u32>]
	Runs an example that either uses an eBPF based Qdisc filter or an u32
	filter to rate limit traffic destined for TCP ports 8080 and 8081. It
	relies on iperf3 to demonstrates the functionality.

	The following are mandatory arguments. Without them prints this help.
	u32         Runs the example with the u32 Qdisc filter
	bpf         Runs the example with the bpf Qdisc filterdiff

	Please look at the script's source code to see how the examples differ.
	EOF
}

### Script main
if [ $# -ne 1 ] || [[ "${1-}" != "bpf" && "${1-}" != "u32" ]]; then
	filter-help
	exit 1
fi
mode="$1"
echo "Starting setup"

# Remove network namespaces if this is the second run
$IP netns delete "$L_NS" &> /dev/null || true
$IP netns delete "$R_NS" &> /dev/null || true

# Create network namespaces
$IP netns add "$L_NS"
$IP netns add "$R_NS"

# Create connected virtual nics
$IP link add "$L_DEV" type veth peer "$R_DEV"

# Add the virtual nics to the network namespaces
$IP link set "$L_DEV" netns "$L_NS"
$IP link set "$R_DEV" netns "$R_NS"

# Add IP addresses to links
$IP -netns "$L_NS" addr add "$L_CIDR" dev "$L_DEV"
$IP -netns "$R_NS" addr add "$R_CIDR" dev "$R_DEV"

# Enable links
$IP -netns "$L_NS" link set "$L_DEV" up
$IP -netns "$R_NS" link set "$R_DEV" up

# Setting up the qdiscs on Left
$TC -netns "$L_NS" qdisc add dev "$L_DEV" root handle 1:0 htb default 30
TC_CLASS_ADD="$TC -netns $L_NS class add dev $L_DEV parent"
$TC_CLASS_ADD 1:0 classid 1:1 htb rate "$LIMIT"
$TC_CLASS_ADD 1:1 classid 1:10 htb rate "$START_RATE" ceil "$P8080_LIMIT"
$TC_CLASS_ADD 1:1 classid 1:20 htb rate "$START_RATE" ceil "$P8081_LIMIT"
$TC_CLASS_ADD 1:1 classid 1:30 htb rate "$START_RATE" ceil "$DEFAULT_LIMIT"

# Setup filters
if [ "$mode" == "bpf" ]; then
	$TC -netns $L_NS filter add dev $L_DEV protocol ip parent 1:0 \
			bpf obj filter.o classid 1: direct-action
else
	U32="$TC -netns $L_NS filter add dev $L_DEV protocol ip parent 1:0 prio 1 u32"
	$U32 match ip dport 8080 FFFF flowid 1:10
	$U32 match ip dport 8081 FFFF flowid 1:20
fi
# Setup iperf3
echo "Starting iperf3"
$IP netns exec "$R_NS" iperf3 -s -p 8080 &> /dev/null &
$IP netns exec "$R_NS" iperf3 -s -p 8081 &> /dev/null &
$IP netns exec "$R_NS" iperf3 -s -p 8082 &> /dev/null &
sleep 1
$IP netns exec "$L_NS" iperf3 -t 4 -c "$R_IP" -p 8080
$IP netns exec "$L_NS" iperf3 -t 4 -c "$R_IP" -p 8081
$IP netns exec "$L_NS" iperf3 -t 4 -c "$R_IP" -p 8082
