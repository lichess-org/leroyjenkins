#!/bin/bash

# Simple wrapper that ensures the ipset sets and firewall rules exist before hammer time

set4=leroy4
set6=leroy6
base_time=30

# IPSet lists, do not error when they already exist, if you want to
# update their properties just delete them manually and call the
# wrapper again
echo "Creating set leroy4"
ipset -exist create $set4 hash:net family inet  timeout $base_time hashsize 16384 forceadd 
echo "Creating set leroy6"
ipset -exist create $set6 hash:net family inet6 timeout $base_time hashsize 16384 forceadd

# Create or flush existing "leroy" chain (for each v4/v6)
if ! iptables -n --list leroy4 >/dev/null 2>/dev/null; then
  iptables -N leroy4
else
  iptables -F leroy4
fi
if ! ip6tables -n --list leroy6 >/dev/null 2>/dev/null; then
  ip6tables -N leroy6
else
  ip6tables -F leroy6
fi

# Add logging rule. LOG is a "non‐terminating target", i.e. rule
# traversal continues at the next rule, cf. man iptables-extensions
iptables  -A leroy4 -m set --match-set leroy4 src -j LOG --log-prefix "Leroyed: "
iptables  -A leroy4 -m set --match-set leroy4 src -j DROP

ip6tables -A leroy6 -m set --match-set leroy6 src -j LOG --log-prefix "Leroyed: "
ip6tables -A leroy6 -m set --match-set leroy6 src -j DROP

# Return to the calling chain for further processing
iptables  -A leroy4 -j RETURN
ip6tables -A leroy6 -j RETURN

# Plug the chain as first item of INPUT
if ! iptables -S INPUT |grep -q '^-A INPUT -j leroy4'; then
  iptables -I INPUT -j leroy4
fi
if ! ip6tables -S INPUT |grep -q '^-A INPUT -j leroy6'; then
  ip6tables -I INPUT -j leroy6
fi

# IPtables rules
if ! iptables  -C INPUT -m set --match-set leroy4 src -j LOG --log-prefix "Leroyed: " 2>/dev/null ; then
  iptables  -I INPUT -m set --match-set leroy4 src -j LOG --log-prefix "Leroyed: "
fi
if ! ip6tables  -C INPUT -m set --match-set leroy6 src -j LOG --log-prefix "Leroyed: " 2>/dev/null ; then
  ip6tables -I INPUT -m set --match-set leroy6 src -j LOG --log-prefix "Leroyed: "
fi


export RUST_LOG=info
tail -F /var/log/nginx/lichess.rate_limit.ip.log | leroyjenkins \
  --bl-ttl=30 \
  --bl-threshold=10 \
  --ipset-base-time=$base_time \
  --ipset-ban-ttl=3600 \
  --ipset-ipv6-name=$set6 \
  --ipset-ipv4-name=$set4 \
  --reporting-ip-time-period=1 \
  --reporting-ban-time-period=5
