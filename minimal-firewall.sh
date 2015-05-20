#!/bin/sh

sudo iptables -A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
sudo iptables -A OUTPUT -m state --state NEW,RELATED,ESTABLISHED -j ACCEPT
sudo iptables -A OUTPUT -j ACCEPT
sudo iptables -N REJECTLOG
sudo iptables -A REJECTLOG -j LOG --log-level debug --log-tcp-sequence --log-tcp-options --log-ip-options -m limit --limit 3/s --limit-burst 8 --log-prefix "REJECT "
sudo iptables -A REJECTLOG -p tcp -j REJECT --reject-with tcp-reset
sudo iptables -A REJECTLOG -j REJECT
sudo iptables -A INPUT -m state --state NEW -p tcp --dport 23 -j ACCEPT
sudo iptables -A INPUT -j REJECTLOG

