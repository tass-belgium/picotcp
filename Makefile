CFLAGS=-Iinclude -Imodules -Wall -ggdb

all:
	mkdir -p build
	gcc -c -o build/pico_stack.o 	stack/pico_stack.c  $(CFLAGS)
	gcc -c -o build/pico_arp.o	stack/pico_arp.c  $(CFLAGS)
	gcc -c -o build/pico_frame.o 	stack/pico_frame.c  $(CFLAGS)
	gcc -c -o build/pico_device.o	stack/pico_device.c  $(CFLAGS)
	gcc -c -o build/pico_protocol.o stack/pico_protocol.c  $(CFLAGS)
	gcc -c -o build/pico_socket.o   stack/pico_socket.c  $(CFLAGS)

mod: modules/pico_ipv4.c modules/pico_dev_vde.c
	mkdir -p build/modules
	gcc -c -o build/modules/pico_ipv4.o modules/pico_ipv4.c $(CFLAGS)
	gcc -c -o build/modules/pico_icmp4.o modules/pico_icmp4.c $(CFLAGS)
	gcc -c -o build/modules/pico_udp.o modules/pico_udp.c $(CFLAGS)
	gcc -c -o build/modules/pico_dev_vde.o modules/pico_dev_vde.c $(CFLAGS)


tst: all mod
	mkdir -p build/test
	gcc -c -o build/vde_test.o test/vde_test.c $(CFLAGS) -ggdb
	gcc -o build/test/vde build/modules/*.o build/*.o -lvdeplug


unit:
	gcc -o build/test/UNIT_arp stack/pico_arp.c stack/pico_frame.c modules/pico_ipv4.c $(CFLAGS) -DUNIT_ARPTABLE -ggdb
clean:
	rm -rf build tags
