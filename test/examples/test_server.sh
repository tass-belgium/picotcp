
killall vde_switch
sudo ./test/vde_sock_start.sh
sudo ./build/test/picoapp.elf --vde pic1:/tmp/pic1.ctl:10.50.0.10:255.255.255.0: -a httpd:
