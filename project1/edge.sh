# dhcp
ip addr add 172.27.0.1/24 dev eupveth
ip addr add 140.114.0.1/24 dev emleftveth
touch /var/lib/dhcp/dhcpd.leases
/usr/sbin/dhcpd -4 -pf /run/dhcp-server-dhcpd.pid -cf /root/edge-dhcpd.conf eupveth

# NAT
iptables -t nat -A POSTROUTING -s 172.27.0.0/24 -o emleftveth -j MASQUERADE

# Routing
route add -net 140.113.0.0/24 gw 140.114.0.2