#!/bin/bash

set -e

sysctl -w net.ipv4.tcp_syncookies=2
sysctl -w net.ipv4.tcp_timestamps=1
sysctl -w net.netfilter.nf_conntrack_tcp_loose=0

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
      PORTS=$(echo "$1" | sed -e 's/^[^=]*=//g')
      shift
      ;;
    *)
      break
      ;;
  esac
done



COMMA=','
if [[ "$PORTS" == *"$COMMA"* ]]; then

   IFS=',' read -ra PORT <<< "$PORTS"
   for p in "${PORT[@]}"; do
     echo $p
     /usr/sbin/iptables -t raw -I PREROUTING -i $INTERFACE -p tcp -m tcp --syn --dport $p $CT
     /usr/sbin/iptables -t filter -A INPUT -i $INTERFACE -p tcp -m tcp --dport $p $SYNPROXY
   done
else 
     /usr/sbin/iptables -t raw -I PREROUTING -i $INTERFACE -p tcp -m tcp --syn --dport $PORTS $CT
     /usr/sbin/iptables -t filter -A INPUT -i $INTERFACE -p tcp -m tcp --dport $PORTS $SYNPROXY
fi

/usr/sbin/iptables -t filter -A INPUT -i $INTERFACE -m state --state INVALID -j DROP
