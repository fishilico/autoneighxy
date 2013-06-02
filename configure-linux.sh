#!/bin/sh
# Configure kernel and firewall to accept what is needed

# You may be more specific by replacing "all" by an interface
echo 1 > /proc/sys/net/ipv4/conf/all/proxy_arp
echo 1 > /proc/sys/net/ipv4/ip_forward
echo 1 > /proc/sys/net/ipv6/conf/all/proxy_ndp
echo 2 > /proc/sys/net/ipv6/conf/all/forwarding

# Please use more specific rules if you know what network prefix your LAN uses
iptables -A FORWARD -j ACCEPT
ip6tables -A FORWARD -j ACCEPT
