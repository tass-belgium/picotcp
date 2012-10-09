CFLAGS=-Iinclude -Imodules -Wall

all:
	mkdir -p build
	gcc -c -o build/pico_stack.o 	stack/pico_stack.c  $(CFLAGS)
	gcc -c -o build/pico_arp.o	stack/pico_arp.c  $(CFLAGS)
	gcc -c -o build/pico_frame.o 	stack/pico_frame.c  $(CFLAGS)
	gcc -c -o build/pico_device.o	stack/pico_device.c  $(CFLAGS)
	gcc -c -o build/pico_protocol.o stack/pico_protocol.c  $(CFLAGS)

mod: modules/pico_ipv4.c modules/pico_dev_vde.c
	mkdir -p build/modules
	gcc -c -o build/modules/pico_ipv4.o modules/pico_ipv4.c $(CFLAGS)
	gcc -c -o build/modules/pico_dev_vde.o modules/pico_dev_vde.c $(CFLAGS)


test:
	mkdir -p build/test
	gcc -o build/test/UNIT_arp stack/pico_arp.c stack/pico_frame.c $(CFLAGS) -DUNIT_ARPTABLE -ggdb

clean:
	rm -rf build tags
