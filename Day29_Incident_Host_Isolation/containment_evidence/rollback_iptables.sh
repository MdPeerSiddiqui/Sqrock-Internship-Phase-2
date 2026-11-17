#!/bin/bash
# Sqrock Incident Response - Emergency Isolation Rollback Script
set -euo pipefail
iptables -F
iptables -X
iptables -P INPUT ACCEPT
iptables -P FORWARD ACCEPT
iptables -P OUTPUT ACCEPT
echo '[+] Network isolation rolled back. Host returned to standard networking.'
