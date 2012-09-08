all: core

dirs:
	mkdir -p build/obj
	mkdir -p build/mod
	mkdir -p build/test
	mkdir -p build/lib
	mkdir -p build/app

core:
	make dirs
	gcc -c -o build/obj/mod_table.o mod_table.c -I include
	gcc -c -o build/obj/delivery.o delivery.c -I include

unit:
	make dirs
	gcc  modules/pico_module_ipv4.c -I include/ -DUNIT_MAIN -ggdb -o build/test/unit_ipv4
	gcc  mod_table.c -I include/ -DUNIT_MAIN -ggdb -o build/test/unit_table


clean:
	rm -rf build
