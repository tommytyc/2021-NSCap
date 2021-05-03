ip fou add port 33333 ipproto 47
ip link add GRE2 type gretap remote 140.113.0.2 local 172.27.0.6 key 1 encap fou encap-sport 33333 encap-dport 55555

ip link set GRE2 up
ip link add br0 type bridge
brctl addif br0 bh2upveth
brctl addif br0 GRE2
ip link set br0 up