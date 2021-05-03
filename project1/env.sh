# init env
contlist=("h1" "h2" "brg1" "brg2" "edge" "middle" "brgr")
# docker stop ${contlist[@]}
# docker rm ${contlist[@]}
docker rmi nscap
docker build -t nscap /home/tommytyc/NSCap/project1

# docker run -it --cap-add=NET_ADMIN --name middle --net=none --privileged nscap
# docker run -it --cap-add=NET_ADMIN --name edge --net=none --privileged nscap
# docker run -it --cap-add=NET_ADMIN --name brgr --net=none --privileged nscap
# docker run -it --cap-add=NET_ADMIN --name brg1 --net=none --privileged nscap
# docker run -it --cap-add=NET_ADMIN --name brg2 --net=none --privileged nscap
# docker run -it --cap-add=NET_ADMIN --name h1 --net=none --privileged nscap
# docker run -it --cap-add=NET_ADMIN --name h2 --net=none --privileged nscap
bash /home/tommytyc/NSCap/project1/init.sh