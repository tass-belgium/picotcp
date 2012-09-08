CTAGS:= -I. -I include/ -DIPV4

all: core

dirs:
	mkdir -p build/obj
	mkdir -p build/mod
	mkdir -p build/test
	mkdir -p build/lib
	mkdir -p build/app

core:
	make dirs
	gcc -c -o build/obj/mod_table.o mod_table.c $(CTAGS)
	gcc -c -o build/obj/delivery.o delivery.c  $(CTAGS)

unit:
	make dirs
	gcc  modules/pico_module_ipv4.c $(CTAGS) -DUNIT_IPV4_MAIN -ggdb -o build/test/unit_ipv4
	gcc  modules/pico_module_ipv4.c mod_table.c $(CTAGS) -DUNIT_TABLE_MAIN -ggdb -o build/test/unit_table 


clean:
	rm -rf build
