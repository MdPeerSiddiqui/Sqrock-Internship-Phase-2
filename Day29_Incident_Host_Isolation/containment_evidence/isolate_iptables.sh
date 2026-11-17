#!/bin/bash
# Sqrock Incident Containment - Emergency iptables Host Quarantine
# Generated for Host: srv-prod-db01.sqrock.internal at 2026-11-17 05:43:04 UTC
set -euo pipefail

# 1. Flush all existing filtering rules
iptables -F
iptables -X
iptables -t nat -F
iptables -t mangle -F

# 2. Set default DROP policies across all chains
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT DROP

# 3. Permit loopback interface for local system functions
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT

# 4. Permit bi-directional traffic exclusively with SOC Bastion Jumpbox (10.0.100.50)
iptables -A INPUT -p tcp -s 10.0.100.50 --dport 22 -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -A OUTPUT -p tcp -d 10.0.100.50 --sport 22 -m state --state ESTABLISHED -j ACCEPT
iptables -A INPUT -p tcp -s 10.0.100.50 --dport 443 -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -A OUTPUT -p tcp -d 10.0.100.50 --sport 443 -m state --state ESTABLISHED -j ACCEPT

# 5. Log all dropped packets for forensic auditing
iptables -A INPUT -m limit --limit 5/min -j LOG --log-prefix 'QUARANTINE_DROP_IN: ' --log-level 4
iptables -A OUTPUT -m limit --limit 5/min -j LOG --log-prefix 'QUARANTINE_DROP_OUT: ' --log-level 4

echo '[+] Host network isolation enforced successfully. Only bastion access permitted.'
