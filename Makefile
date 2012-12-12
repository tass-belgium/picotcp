CC=$(CROSS_COMPILE)gcc
#STMCFLAGS = -mcpu=cortex-m4 -mthumb -mlittle-endian -mfpu=fpv4-sp-d16 -mfloat-abi=hard -mthumb-interwork -fsingle-precision-constant

CFLAGS=-Iinclude -Imodules -Wall -ggdb $(STMCFLAGS)
#CFLAGS=-Iinclude -Imodules -Wall -Os $(STMCFLAGS)




all:
	mkdir -p build/lib
	$(CC) -c -o build/lib/pico_stack.o 	stack/pico_stack.c  $(CFLAGS)
	$(CC) -c -o build/lib/pico_arp.o	stack/pico_arp.c  $(CFLAGS)
	$(CC) -c -o build/lib/pico_frame.o 	stack/pico_frame.c  $(CFLAGS)
	$(CC) -c -o build/lib/pico_device.o	stack/pico_device.c  $(CFLAGS)
	$(CC) -c -o build/lib/pico_protocol.o stack/pico_protocol.c  $(CFLAGS)
	$(CC) -c -o build/lib/pico_socket.o   stack/pico_socket.c  $(CFLAGS)

mod: modules/pico_ipv4.c modules/pico_dev_loop.c
	mkdir -p build/modules
	$(CC) -c -o build/modules/pico_ipv4.o modules/pico_ipv4.c $(CFLAGS)
	$(CC) -c -o build/modules/pico_icmp4.o modules/pico_icmp4.c $(CFLAGS)
	$(CC) -c -o build/modules/pico_udp.o modules/pico_udp.c $(CFLAGS)
	$(CC) -c -o build/modules/pico_tcp.o modules/pico_tcp.c $(CFLAGS)
	$(CC) -c -o build/modules/pico_dev_loop.o modules/pico_dev_loop.c $(CFLAGS)

posix: mod modules/pico_dev_vde.c modules/pico_dev_tun.c
	$(CC) -c -o build/modules/pico_dev_vde.o modules/pico_dev_vde.c $(CFLAGS)
	$(CC) -c -o build/modules/pico_dev_tun.o modules/pico_dev_tun.c $(CFLAGS)
	$(CC) -c -o build/modules/pico_ptsocket.o modules/pico_ptsocket.c $(CFLAGS) 

tst: all posix
	mkdir -p build/test
	$(CC) -c -o build/vde_test.o test/vde_test.c $(CFLAGS) -ggdb
	$(CC) -c -o build/vde_receiver.o test/vde_receiver.c $(CFLAGS) -ggdb
	$(CC) -c -o build/vde_send.o test/vde_send.c $(CFLAGS) -ggdb
	$(CC) -c -o build/echoclient.o test/echoclient.c $(CFLAGS) -ggdb
	$(CC) -c -o build/echoclientUDP.o test/echoclientUDP.c $(CFLAGS) -ggdb
	$(CC) -c -o build/sendclient.o test/sendclient.c $(CFLAGS) -ggdb
	$(CC) -o build/test/vde build/modules/*.o build/lib/*.o build/vde_test.o -lvdeplug
	$(CC) -o build/test/rcv build/modules/*.o build/lib/*.o build/vde_receiver.o -lvdeplug
	$(CC) -o build/test/send build/modules/*.o build/lib/*.o build/vde_send.o -lvdeplug
	$(CC) -o build/test/echo build/modules/*.o build/lib/*.o build/echoclient.o -lvdeplug
	$(CC) -o build/test/send2 build/modules/*.o build/lib/*.o build/sendclient.o -lvdeplug
	$(CC) -o build/test/echoUDP build/modules/*o build/lib/*.o build/echoclientUDP.o -lvdeplug

loop: all mod
	mkdir -p build/test
	$(CC) -c -o build/modules/pico_dev_loop.o modules/pico_dev_loop.c $(CFLAGS)
	$(CC) -c -o build/loop_ping.o test/loop_ping.c $(CFLAGS) -ggdb

lib: all mod
	mkdir -p build/lib
	mkdir -p build/include
	cp -f include/*.h build/include
	cp -fa include/arch build/include
	cp -f modules/*.h build/include
	$(CROSS_COMPILE)ar cru build/lib/picotcp.a build/modules/*.o build/lib/*.o
	$(CROSS_COMPILE)ranlib build/lib/picotcp.a

unit:
	$(CC) -o build/test/UNIT_arp stack/pico_arp.c stack/pico_frame.c modules/pico_ipv4.c $(CFLAGS) -DUNIT_ARPTABLE -ggdb

clean:
	rm -rf build tags
