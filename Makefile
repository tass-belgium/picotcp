all: modules
	gcc -c pico_stack.c -Wall
	gcc -c pico_arp.c -Wall
	gcc -c pico_frame.c -Wall
	gcc -c pico_device.c -Wall
	gcc -c pico_protocol.c -Wall

modules:
	gcc -c pico_ipv4.c -Wall
	gcc -c pico_dev_vde.c -Wall


unit:
	gcc -o UNIT_arp pico_arp.c pico_frame.c -Wall -DUNIT_ARPTABLE -ggdb

clean:
	rm -f *.o UNIT_*
