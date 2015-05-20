#!/bin/sh

sudo iptables -D INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
sudo iptables -D OUTPUT -m state --state NEW,RELATED,ESTABLISHED -j ACCEPT
sudo iptables -D OUTPUT -j ACCEPT
#sudo iptables -N REJECTLOG
sudo iptables -D REJECTLOG -j LOG --log-level debug --log-tcp-sequence --log-tcp-options --log-ip-options -m limit --limit 3/s --limit-burst 8 --log-prefix "REJECT "
sudo iptables -D REJECTLOG -p tcp -j REJECT --reject-with tcp-reset
sudo iptables -D REJECTLOG -j REJECT
sudo iptables -D INPUT -m state --state NEW -p tcp --dport 23 -j ACCEPT
sudo iptables -D INPUT -j REJECTLOG

