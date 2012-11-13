CFLAGS=-Iinclude -Imodules -Wall -ggdb
#CFLAGS=-Iinclude -Imodules -Wall -Os

all:
	mkdir -p build/lib
	gcc -c -o build/lib/pico_stack.o 	stack/pico_stack.c  $(CFLAGS)
	gcc -c -o build/lib/pico_arp.o	stack/pico_arp.c  $(CFLAGS)
	gcc -c -o build/lib/pico_frame.o 	stack/pico_frame.c  $(CFLAGS)
	gcc -c -o build/lib/pico_device.o	stack/pico_device.c  $(CFLAGS)
	gcc -c -o build/lib/pico_protocol.o stack/pico_protocol.c  $(CFLAGS)
	gcc -c -o build/lib/pico_socket.o   stack/pico_socket.c  $(CFLAGS)

mod: modules/pico_ipv4.c modules/pico_dev_vde.c modules/pico_dev_tun.c
	mkdir -p build/modules
	gcc -c -o build/modules/pico_ipv4.o modules/pico_ipv4.c $(CFLAGS)
	gcc -c -o build/modules/pico_icmp4.o modules/pico_icmp4.c $(CFLAGS)
	gcc -c -o build/modules/pico_udp.o modules/pico_udp.c $(CFLAGS)
	gcc -c -o build/modules/pico_tcp.o modules/pico_tcp.c $(CFLAGS)
	gcc -c -o build/modules/pico_dev_vde.o modules/pico_dev_vde.c $(CFLAGS)
	gcc -c -o build/modules/pico_dev_tun.o modules/pico_dev_tun.c $(CFLAGS)


tst: all mod
	mkdir -p build/test
	gcc -c -o build/vde_test.o test/vde_test.c $(CFLAGS) -ggdb
	gcc -c -o build/vde_receiver.o test/vde_receiver.c $(CFLAGS) -ggdb
	gcc -c -o build/vde_send.o test/vde_send.c $(CFLAGS) -ggdb
	gcc -c -o build/echoclient.o test/echoclient.c $(CFLAGS) -ggdb
	gcc -o build/test/vde build/modules/*.o build/lib/*.o build/vde_test.o -lvdeplug
	gcc -o build/test/rcv build/modules/*.o build/lib/*.o build/vde_receiver.o -lvdeplug
	gcc -o build/test/send build/modules/*.o build/lib/*.o build/vde_send.o -lvdeplug
	gcc -o build/test/echo build/modules/*.o build/lib/*.o build/echoclient.o -lvdeplug


unit:
	gcc -o build/test/UNIT_arp stack/pico_arp.c stack/pico_frame.c modules/pico_ipv4.c $(CFLAGS) -DUNIT_ARPTABLE -ggdb
clean:
	rm -rf build tags
