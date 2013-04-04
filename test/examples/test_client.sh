
# kill vde_switch, vde_sock_start and vde_sock_start_user are not compatible
sudo killall vde_switch
sudo ./test/vde_sock_start.sh

echo 1 > /proc/sys/net/ipv4/ip_forward
iptables -t nat -A POSTROUTING -o wlan0 -j MASQUERADE
iptables -A FORWARD -i pic0 -o wlan0 -j ACCEPT
iptables -A FORWARD -i wlan0 -o pic0 -j ACCEPT

./build/test/picoapp.elf --vde pic0:/tmp/pic0.ctl:10.40.0.2:255.255.255.0:10.40.0.1: -a wget:web.mit.edu/modiano/www/6.263/lec22-23.pdf
