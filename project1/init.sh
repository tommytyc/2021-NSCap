# call up all container
modprobe fou
contlist=("h1" "h2" "brg1" "brg2" "edge" "middle" "brgr")
docker stop ${contlist[@]}
docker rm ${contlist[@]}
docker run -it -d --cap-add=NET_ADMIN --name middle --net=none --privileged nscap
docker run -it -d --cap-add=NET_ADMIN --name edge --net=none --privileged nscap
docker run -it -d --cap-add=NET_ADMIN --name brgr --net=none --privileged nscap
docker run -it -d --cap-add=NET_ADMIN --name brg1 --net=none --privileged nscap
docker run -it -d --cap-add=NET_ADMIN --name brg2 --net=none --privileged nscap
docker run -it -d --cap-add=NET_ADMIN --name h1 --net=none --privileged nscap
docker run -it -d --cap-add=NET_ADMIN --name h2 --net=none --privileged nscap

iptables -P FORWARD ACCEPT

# add br0
brctl delbr br0
brctl addbr br0

# BRG1 h1
ip link add bh1downveth type veth peer name bh1upveth
ip link set bh1downveth netns $(docker inspect -f '{{.State.Pid}}' h1)
ip link set bh1upveth netns $(docker inspect -f '{{.State.Pid}}' brg1)
docker exec h1 bash -c "ip link set bh1downveth up"
docker exec brg1 bash -c "ip link set bh1upveth up"

# BRG2 h2
ip link add bh2downveth type veth peer name bh2upveth
ip link set bh2downveth netns $(docker inspect -f '{{.State.Pid}}' h2)
ip link set bh2upveth netns $(docker inspect -f '{{.State.Pid}}' brg2)
docker exec h2 bash -c "ip link set bh2downveth up"
docker exec brg2 bash -c "ip link set bh2upveth up"

# edge middle
ip link add emleftveth type veth peer name emrightveth
ip link set emleftveth netns $(docker inspect -f '{{.State.Pid}}' edge)
ip link set emrightveth netns $(docker inspect -f '{{.State.Pid}}' middle)
docker exec edge bash -c "ip link set emleftveth up"
docker exec middle bash -c "ip link set emrightveth up"

# middle brgr
ip link add mbleftveth type veth peer name mbrightveth
ip link set mbleftveth netns $(docker inspect -f '{{.State.Pid}}' middle)
ip link set mbrightveth netns $(docker inspect -f '{{.State.Pid}}' brgr)
docker exec middle bash -c "ip link set mbleftveth up"
docker exec brgr bash -c "ip link set mbrightveth up"

# brgr vm(gwr)
ip link add brvmupveth type veth peer name brvmdownveth
ip link set brvmupveth netns $(docker inspect -f '{{.State.Pid}}' brgr)
docker exec brgr bash -c "ip link set brvmupveth up"
ip link set brvmdownveth up
ip addr add 20.0.0.1/8 dev brvmdownveth

# all about br0
# brg1 br0
ip link add 1downveth type veth peer name 1upveth
ip link set 1downveth netns $(docker inspect -f '{{.State.Pid}}' brg1)
docker exec brg1 bash -c "ip link set 1downveth up"
brctl addif br0 1upveth
ip link set 1upveth up

# brg2 br0
ip link add 2downveth type veth peer name 2upveth
ip link set 2downveth netns $(docker inspect -f '{{.State.Pid}}' brg2)
docker exec brg2 bash -c "ip link set 2downveth up"
brctl addif br0 2upveth
ip link set 2upveth up

# edge br0
ip link add eupveth type veth peer name edownveth
ip link set eupveth netns $(docker inspect -f '{{.State.Pid}}' edge)
docker exec edge bash -c "ip link set eupveth up"
brctl addif br0 edownveth
ip link set edownveth up

ip link set br0 up

# cp and run each script of node
docker cp ./edge.sh edge:/root/script.sh
docker cp ./edge-dhcpd.conf edge:/root/edge-dhcpd.conf
docker exec edge bash -c "bash /root/script.sh"

bash /home/tommytyc/NSCap/project1/dhcp.sh

docker cp ./middle.sh middle:/root/script.sh
docker exec middle bash -c "bash /root/script.sh"

docker cp ./brgr.sh brgr:/root/script.sh
docker cp ./0616078.cpp brgr:/root/0616078.cpp
docker cp ./gre.h brgr:/root/gre.h
docker cp ./libpcap-1.10.0 brgr:/root/libpcap
docker exec brgr bash -c "bash /root/script.sh"
docker exec brgr bash -c "route add -net 140.114.0.0/24 gw 140.113.0.1"
docker exec brgr bash -c "/sbin/ldconfig -v"

docker cp ./brg1.sh brg1:/root/script.sh
docker exec brg1 bash -c "bash /root/script.sh"

docker cp ./brg2.sh brg2:/root/script.sh
docker exec brg2 bash -c "bash /root/script.sh"