#!/bin/bash

# Simple wrapper that ensures the ipset sets and firewall rules exist before hammer time

set4=leroy4
set6=leroy6
base_time=100

# IPSet lists, do not error when they already exist, if you want to
# update their properties just delete them manually and call the
# wrapper again
echo "Creating set leroy4"
ipset -exist create $set4 hash:net family inet  timeout $base_time hashsize 16384 forceadd
echo "Creating set leroy6"
ipset -exist create $set6 hash:net family inet6 timeout $base_time hashsize 16384 forceadd

# IPtables rules
if ! iptables  -C INPUT -m set --match-set leroy4 src -j LOG 2>/dev/null ; then
  iptables  -I INPUT -m set --match-set leroy4 src -j LOG
fi
if ! ip6tables  -C INPUT -m set --match-set leroy6 src -j LOG 2>/dev/null ; then
  ip6tables -I INPUT -m set --match-set leroy6 src -j LOG
fi

export RUST_LOG=info
leroyjenkins \
  --bl-file=/var/log/nginx/lichess.rate_limit.ip.log \
  --bl-ttl=60 \
  --bl-threshold=20 \
  --ipset-base-time=$base_time \
  --ipset-ban-ttl=86400 \
  --ipset-ipv6-name=$set6 \
  --ipset-ipv4-name=$set4 \
  --reporting-ip-time-period=5 \
  --reporting-ban-time-period=60

