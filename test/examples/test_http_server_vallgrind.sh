
sudo killall vde_switch
sudo ./test/vde_sock_start.sh
sudo valgrind --leak-check=yes ./build/test/test_http_server.elf --vde pic1:/tmp/pic1.ctl:10.50.0.10:255.255.255.0:
