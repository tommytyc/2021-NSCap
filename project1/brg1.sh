ip fou add port 33333 ipproto 47
ip link add GRE type gretap remote 140.113.0.2 local 172.27.0.5 key 0 encap fou encap-sport 33333 encap-dport 55555

ip link set GRE up
ip link add br0 type bridge
brctl addif br0 bh1upveth
brctl addif br0 GRE
ip link set br0 up