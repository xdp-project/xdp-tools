#!/bin/bash

set -e

SYNPROXY="-m state --state INVALID,UNTRACKED -j SYNPROXY --sack-perm --timestamp --wscale 7 --mss 1460"
TCPOPTIONS="--mss4 1460 --mss6 1440 --wscale 7 --ttl 64"

while test $# -gt 0; do
  case "$1" in
    --ports*)
      # shellcheck disable=SC2001
      # the below sed is to support both formats "--flag value" and "--flag=value"
      PORTS=$(echo "$1" | sed -e 's/^[^=]*=//g')
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

        for p in $(echo $PORTS | sed 's/,/ /g')
        do
		raw_spec=$(iptables -t raw -S | grep -w $p | sed -e 's/^\-A/\-D/')
                iptables -t raw $raw_spec
		filter_spec=$(iptables -S | grep -w $p | sed -e 's/^\-A/\-D/')
                iptables $filter_spec
		if [ $? -eq 0 ]
		then
			echo "$p is removed from allowed ports\n"
		else
			echo "$p failed to be removed from allowed ports\n"
		fi
        done

	echo "========================================================================="
	echo "make sure ports in iptable rules matches port in allowed_ports map"
	echo "run xdp_synproxy --prog <syncookie_xdp prog id> --ports <all allowd ports>
		 to update allowed_ports map!"
	echo ""
	echo "current allowed_ports protected by synproxy"
	echo ""
	bpftool map dump name allowed_ports
	echo ""
	echo "current SYNPROXY iptable rules"
	iptables -n -L --line-numbers | grep SYNPROXY
else
	echo "syncookie_xdp not attached!"
fi
