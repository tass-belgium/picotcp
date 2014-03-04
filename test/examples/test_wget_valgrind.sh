killall vde_switch
sudo ./test/vde_sock_start.sh

sudo sh -c "echo 1 > /proc/sys/net/ipv4/ip_forward"
sudo iptables -t nat -A POSTROUTING -o wlan0 -j MASQUERADE
sudo iptables -A FORWARD -i pic0 -o wlan0 -j ACCEPT
sudo iptables -A FORWARD -i wlan0 -o pic0 -j ACCEPT

#valgrind ./build/test/picoapp.elf --vde pic0:/tmp/pic0.ctl:10.40.0.10:255.255.255.0:10.40.0.1 -a wget:ftp.belnet.be/PortablePython/v2.7/PortablePython_2.7.2.1.exe
#valgrind --leak-check=full --show-leak-kinds=all ./build/test/picoapp.elf --vde pic0:/tmp/pic0.ctl:10.40.0.10:255.255.255.0:10.40.0.1 -a wget:ftp.belnet.be/debian/tools/win32-loader/oldstable/win32-loader.exe
#valgrind --track-origins=yes --leak-check=full -v ./build/test/picoapp.elf --vde pic0:/tmp/pic0.ctl:10.40.0.10:255.255.255.0:10.40.0.1 -a wget:ftp.belnet.be/debian/tools/win32-loader/oldstable/win32-loader.exe
valgrind --track-origins=yes --leak-check=full -v ./build/test/picoapp.elf --vde pic0:/tmp/pic0.ctl:10.40.0.10:255.255.255.0:10.40.0.1 -a wget:ftp.belnet.be/debian/dists/wheezy/Contents-i386.gz
