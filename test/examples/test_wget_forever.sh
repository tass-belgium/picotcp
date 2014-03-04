killall vde_switch
sudo ./test/vde_sock_start.sh

sudo sh -c "echo 1 > /proc/sys/net/ipv4/ip_forward"
sudo iptables-save > iptable_saved
sudo iptables --flush
sudo iptables -t nat -A POSTROUTING -o wlan0 -j MASQUERADE
sudo iptables -A FORWARD -i pic0 -o wlan0 -j ACCEPT
sudo iptables -A FORWARD -i wlan0 -o pic0 -j ACCEPT

gdb --args ./build/test/picoapp.elf --vde pic0:/tmp/pic0.ctl:10.40.0.10:255.255.255.0:10.40.0.1 -a wget_forever

sudo iptables-restore iptable_saved

