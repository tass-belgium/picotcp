killall vde_switch

sudo sh -c "echo 1 > /proc/sys/net/ipv4/ip_forward"
sudo iptables-save > iptable_saved
sudo iptables --flush
sudo iptables -t nat -A POSTROUTING -o wlan0 -j MASQUERADE
sudo iptables -A FORWARD -i tun0 -o wlan0 -j ACCEPT
sudo iptables -A FORWARD -i wlan0 -o tun0 -j ACCEPT

$(sleep 3 && sudo ifconfig tun0 10.70.0.1/24 up) &
#sudo ./build/test/picoapp.elf --tun tun0:10.70.0.10:255.255.255.0:10.70.0.1 -a wget_forever:10.70.0.1/STM32F4xx_Clock_Configuration_V1.1.0_configured.xls:10.70.0.1/zMidi_synth-debug-unaligned.apk:10.70.0.1/module3/libopencm3.tar.bz2
sudo ./build/test/picoapp.elf --tun tun0:10.70.0.10:255.255.255.0:10.70.0.1 -a wget_forever:10.70.0.1/test1.bin:10.70.0.1/test10.bin:10.70.0.1/test5.bin:
#sudo gdb --args ./build/test/picoapp.elf --tun tun0:10.70.0.10:255.255.255.0:10.70.0.1 -a wget_forever:10.70.0.1/STM32F4xx_Clock_Configuration_V1.1.0_configured.xls:10.70.0.1/zMidi_synth-debug-unaligned.apk:10.70.0.1/module3/libopencm3.tar.bz2
sudo iptables-restore iptable_saved

