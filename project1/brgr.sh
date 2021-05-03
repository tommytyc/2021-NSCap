ip addr add 140.113.0.2/24 dev mbrightveth
ip addr add 20.0.0.2/8 dev brvmupveth
ip fou add port 55555 ipproto 47

# auto tunnel creation
echo "include /usr/local/lib/" >> /etc/ld.so.conf
cd /root/libpcap/
./configure
make
make install
cd ../
g++ /root/0616078.cpp -lpcap

ip link add br0 type bridge
brctl addif br0 brvmupveth
