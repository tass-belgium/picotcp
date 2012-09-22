CFLAGS:= -I. -I include/ -DIPV4 -Wall -g -ggdb

all: core

dirs:
	mkdir -p build/obj
	mkdir -p build/test
	mkdir -p build/lib
	mkdir -p build/app

core:
	make dirs
	gcc -c -o build/obj/mod_table.o src/mod_table.c $(CFLAGS) $(EXTRA)
	gcc -c -o build/obj/delivery.o src/delivery.c  $(CFLAGS)  $(EXTRA)

modules: build/mod
build/mod:
	mkdir -p build/mod
	gcc -c -o build/mod/pico_module_ipv4.o modules/pico_module_ipv4.c $(CFLAGS) $(EXTRA)

ip4unit: core
	make dirs
	make core
	rm -f build/mod/pico_module_ipv4.o
	gcc -c -o build/mod/pico_module_ipv4.o modules/pico_module_ipv4.c $(CFLAGS) -DUNIT_IPV4_MAIN
	gcc  build/obj/* build/mod/* -o build/test/unit_ipv4

unit: clean
	make dirs
	make core EXTRA=-DUNIT_TABLE_MAIN
	make modules
	gcc  build/obj/* build/mod/* -o build/test/unit_table


clean:
	rm -rf build
