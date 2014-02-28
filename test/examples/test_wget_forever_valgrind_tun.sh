killall vde_switch

sudo sh -c "echo 1 > /proc/sys/net/ipv4/ip_forward"
sudo iptables-save > iptable_saved
sudo iptables --flush
sudo iptables -t nat -A POSTROUTING -o wlan0 -j MASQUERADE
sudo iptables -A FORWARD -i pic0 -o wlan0 -j ACCEPT
sudo iptables -A FORWARD -i wlan0 -o pic0 -j ACCEPT

sudo valgrind --track-origins=yes --leak-check=full -v ./build/test/picoapp.elf --tun tun0:10.70.0.10:255.255.255.0:10.70.0.1 -a wget_forever &
sleep 2
sudo ifconfig tun0 10.70.0.1/24 up
fg
sudo iptables-restore iptable_saved

