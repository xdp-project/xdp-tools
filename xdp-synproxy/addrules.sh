#!/bin/bash

set -e

SYNPROXY="-m state --state INVALID,UNTRACKED -j SYNPROXY --sack-perm --timestamp --wscale 7 --mss 1460"
CT="-j CT --notrack"

while test $# -gt 0; do
  case "$1" in
    --interface*)
      # shellcheck disable=SC2001
      # the below sed is to support both formats "--flag value" and "--flag=value"
      INTERFACE=$(echo "$1" | sed -e 's/^[^=]*=//g')
      shift
      ;;
    --ports*)
      # shellcheck disable=SC2001
      # the below sed is to support both formats "--flag value" and "--flag=value"
      SYNPROXY_PORTS=$(echo "$1" | sed -e 's/^[^=]*=//g')
      shift
      ;;
    --tcpopts*)
      # shellcheck disable=SC2001
      # the below sed is to support both formats "--flag value" and "--flag=value"
      TCPOPTIONS=$(echo "$1" | sed -e 's/^[^=]*=//g')
      shift
      ;;
    *)
      break
      ;;
  esac
done

prog_id=$(bpftool prog | grep syncookie_xdp | cut -d':' -f1)

if [ ! -z "$prog_id" ]; then
        sysctl -w net.ipv4.tcp_syncookies=2
        sysctl -w net.ipv4.tcp_timestamps=1
        sysctl -w net.netfilter.nf_conntrack_tcp_loose=0
        TCPOPTIONS="--mss4 1460 --mss6 1440 --wscale 7 --ttl 64"
        SYNPROXY="-m state --state INVALID,UNTRACKED -j SYNPROXY --sack-perm --timestamp --wscale 7 --mss 1460"
        CT="-j CT --notrack"
        RULE_COMMENT="-m comment --comment "XDPSYNPROXY""
        LINE=1

        for p in $(echo $SYNPROXY_PORTS | sed 's/,/ /g')
        do
                iptables -t raw -I PREROUTING $LINE -i $INTERFACE $RULE_COMMENT -p tcp -m tcp --syn --dport $p $CT
                iptables -I INPUT $LINE -i $INTERFACE $RULE_COMMENT -p tcp -m tcp --dport $p $SYNPROXY
                ((LINE=LINE+1))
		if [ $? -eq 0 ]
		then
			echo "$p is added to allowed ports\n"
		else
			echo "$p is failed to be added to allowed ports\n"
		fi
        done

        iptables -t filter -A INPUT -i $INTERFACE -m state --state INVALID -j DROP
        xdp_synproxy --prog $prog_id $TCPOPTIONS --ports $SYNPROXY_PORTS

	echo "make sure ports in iptable rules matches port in allowed_ports map"
	echo "if not, run xdp_synproxy to update allowed_ports map!"
	echo "current allowed_ports protected by synproxy"
	bpftool map dump name allowed_ports
	echo "current SYNPROXY iptable rules"
	iptables -n -L --line-numbers | grep SYNPROXY
else
	echo "syncookie_xdp not attached!"
fi
