vdecmd -s /tmp/pico.mgmt shutdown
vdecmd -s /tmp/pici.mgmt shutdown

vde_switch -s /tmp/pic0.ctl -m 777 -M /tmp/pico.mgmt -d -hub -t vde0
vde_switch -s /tmp/pic1.ctl -m 777 -M /tmp/pici.mgmt -d -hub -t vde1

ifconfig vde0 10.50.0.1 netmask 255.255.0.0
ifconfig vde1 10.40.0.1 netmask 255.255.0.0

valgrind --leak-check=full ./build/test/picoapp.elf --vde pic0:/tmp/pic0.ctl:10.50.0.8:255.255.0.0:10.50.0.1: --vde pic1:/tmp/pic1.ctl:10.40.0.11:255.255.0.0:10.40.0.1: -a bcast:
